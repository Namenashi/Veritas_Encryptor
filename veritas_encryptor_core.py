import os
import json
import struct
import secrets
import ctypes
import logging
import tempfile
import shutil
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidTag
from argon2 import PasswordHasher, Type
from dataclasses import dataclass
from typing import Optional, List, Dict, Any, Tuple, Callable
from pathlib import Path
from contextlib import contextmanager
from logger import *



@dataclass
class VeritasMetadata:
    """Metadata for encrypted files"""
    original_size: int
    timestamp: int
    version: int
    extension: str  # Original file extension
    
    def to_json(self) -> str:
        """Convert metadata to JSON string"""
        data = {
            'original_size': self.original_size,
            'timestamp': self.timestamp,
            'version': self.version,
            'extension': self.extension
        }
        return json.dumps(data, ensure_ascii=False)
    
    def to_bytes(self) -> bytes:
        """Convert metadata to bytes"""
        return self.to_json().encode('utf-8')
    
    @classmethod
    def from_json(cls, json_str: str) -> 'VeritasMetadata':
        """Create metadata object from JSON string"""
        try:
            data = json.loads(json_str)
            return cls(
                original_size=int(data['original_size']),
                timestamp=int(data['timestamp']),
                version=int(data['version']),
                extension=str(data.get('extension', ''))  # Default '' for backward compatibility
            )
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            raise VeritasFileError("Metadata format is corrupted") from e
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'VeritasMetadata':
        """Create metadata object from bytes"""
        try:
            return cls.from_json(data.decode('utf-8'))
        except UnicodeDecodeError as e:
            raise VeritasFileError("Invalid metadata encoding") from e



class SecureMemory:
    """
    Class responsible for secure memory management

    This class is used to securely store and manage sensitive data.
    It provides OS-level memory locking and security features to protect data.

    Key features:
    - Memory page locking and unlocking:
      Locks memory areas containing sensitive data to prevent them from being
      exported to other processes or swap space. This maintains data confidentiality.
      
    - Secure buffer allocation and deallocation:
      Allocates special buffers for storing sensitive data.
      These buffers are located in locked memory areas and can safely store and manage data.
      Buffers are securely deallocated when no longer needed, with immediate data removal.

    - Secure buffer content deletion:
      Provides functionality to securely delete data stored in secure buffers.
      Performs multiple overwrites during deletion to make data recovery difficult.
      
    - Tracking and cleanup of all allocated secure buffers:
      Tracks all secure buffers allocated within the program.
      Automatically and securely deallocates and cleans up tracked buffers on program termination.
      This prevents memory leaks and ensures secure data deletion.

    Usage example:
    secure_mem = SecureMemory()
    buffer = secure_mem.secure_buffer(size)
    # Use buffer
    ...
    secure_mem.secure_free(buffer)
    """
    
    def __init__(self):
        """
        SecureMemory class constructor
        
        Initializes libraries needed for memory locking and creates a list to track locked pages.
        """
        self._locked_pages = []
        self._allocated_size = 0  # Track total allocated memory
        self._platform = os.name
        
        # Initialize libc
        if self._platform == 'posix':
            try:
                self._libc = ctypes.CDLL('libc.so.6')
                self._libc.mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                self._libc.munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                self._libc.mlock.restype = ctypes.c_int
                self._libc.munlock.restype = ctypes.c_int
            except Exception as e:
                raise VeritasMemoryError("Failed to initialize libc") from e
                
        elif self._platform == 'nt':
            try:
                self._kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
                self._kernel32.VirtualLock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                self._kernel32.VirtualUnlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                self._kernel32.VirtualLock.restype = ctypes.c_bool
                self._kernel32.VirtualUnlock.restype = ctypes.c_bool
            except Exception as e:
                raise VeritasMemoryError("Failed to initialize Kernel32") from e
    
    def secure_buffer(self, size: int) -> ctypes.Array:
        """
        Function to allocate a secure buffer

        Args:
            size: Size of buffer to allocate (bytes)

        Returns:
            Allocated secure buffer (ctypes.Array)

        Raises:
            VeritasMemoryError: On secure buffer allocation failure
        """
        try:
            buffer = ctypes.create_string_buffer(size)
            addr = ctypes.addressof(buffer)
            
            # Track memory allocation
            self._allocated_size += size
            if self._allocated_size > 2 * 1024 * 1024:  # 2GB limit
                raise VeritasMemoryError("Memory allocation limit exceeded")
                
            # Lock memory pages
            if self._platform == 'posix':
                if self._libc.mlock(addr, size) != 0:
                    raise VeritasMemoryError("Failed to lock memory pages")
            elif self._platform == 'nt':
                if not self._kernel32.VirtualLock(addr, size):
                    error = ctypes.get_last_error()
                    raise VeritasMemoryError(f"Failed to lock memory pages (Error code: {error})")
            
            # Add to tracking list only if locking succeeds
            self._locked_pages.append((addr, size, buffer))
            return buffer
            
        except Exception as e:
            if 'buffer' in locals():
                try:
                    # Immediately delete buffer on failure
                    ctypes.memset(addr, 0, size)
                    del buffer
                except:
                    pass
            raise VeritasMemoryError("Failed to allocate secure buffer") from e
    
    def _verify_pattern(self, addr: int, pattern: int, size: int) -> bool:
        """
        Function to verify memory contents against a specific pattern
        
        This function is used by secure_free to verify memory deletion.
        It verifies that memory contents have been overwritten with the specified pattern
        to ensure secure deletion.
        
        Args:
            addr: Memory address to verify
            pattern: Pattern to verify against (0x00, 0xFF etc)
            size: Size of memory to verify

        Returns:
            Whether memory contents match the pattern
        """
        try:
            # Create verification buffer
            verify_buffer = (ctypes.c_ubyte * size)()
            ctypes.memmove(verify_buffer, addr, size)
            
            # Verify all bytes match the pattern
            return all(b == pattern for b in verify_buffer)
            
        except Exception as e:
            logger.error(f"Pattern verification failed: {e}")
            return False

    def secure_free(self, buffer: ctypes.Array) -> None:
        """
        Function to securely free and delete contents of a secure buffer

        Args:
            buffer: Secure buffer to free (ctypes.Array)

        Raises:
            VeritasMemoryError: On buffer deallocation failure
        """
        if not buffer:
            return
            
        addr = ctypes.addressof(buffer)
        size = len(buffer)
        
        try:
            # First check if page is locked
            if not any(addr == a for a, _, _ in self._locked_pages):
                raise VeritasMemoryError("Unlocked memory page")
            
            # Complete buffer content deletion (multiple patterns)
            patterns = [0x00, 0xFF, 0xAA, 0x55]
            for pattern in patterns:
                # Overwrite with pattern
                ctypes.memset(addr, pattern, size)
                
                # Add memory barrier
                ctypes.memmove(addr, addr, size)
                
                # Verify pattern
                if not self._verify_pattern(addr, pattern, size):
                    raise VeritasMemoryError(f"Memory pattern {hex(pattern)} verification failed")
            
            # Finally initialize to 0 and verify
            ctypes.memset(addr, 0, size)
            if not self._verify_pattern(addr, 0, size):
                raise VeritasMemoryError("Final memory initialization verification failed")
            
            # Unlock memory
            if self._platform == 'posix':
                if self._libc.munlock(addr, size) != 0:
                    raise VeritasMemoryError("Failed to unlock memory pages")
            elif self._platform == 'nt':
                if not self._kernel32.VirtualUnlock(addr, size):
                    error = ctypes.get_last_error()
                    raise VeritasMemoryError(f"Failed to unlock memory pages (Error code: {error})")
            
            # Remove from tracking list
            self._locked_pages = [(a, s, b) for a, s, b in self._locked_pages if a != addr]
            
        except Exception as e:
            logger.error("Failed to free secure memory", exc_info=True)
            raise VeritasMemoryError("Failed to free secure memory") from e
        
    def __del__(self):
        """
        SecureMemory class destructor

        Safely deallocates and cleans up all allocated secure buffers on program termination.
        Records warning messages in log if deallocation fails.
        """
        errors = []
        for addr, size, buffer in self._locked_pages[:]:  # Iterate over copy
            try:
                self.secure_free(buffer)
            except Exception as e:
                errors.append(str(e))
                logger.error(f"Failed to free secure memory: {e}")
        
        if errors:
            logger.error(f"Some memory cleanup failed: {', '.join(errors)}")



class SecureFile:
    """
    Class responsible for secure file handling

    This class is used to safely handle files when storing and loading sensitive data.
    Provides functionality for creating and securely deleting temporary files to maintain data confidentiality.

    Key features:
    - Secure temporary file creation:
      Creates files used for temporary storage of sensitive data.
      These files have restricted permissions so only authorized users can access them.

    - Secure file deletion:
      Provides functionality to securely delete temporary files.
      Overwrites file contents multiple times and completely removes from the file system
      to make data recovery difficult.

    - File permission setting:
      Restricts permissions on temporary files so only authorized users can access them.
      This maintains file confidentiality.

    Usage example:
    with SecureFile.secure_tempfile() as (temp_file, temp_path):
        # Use temporary file
        temp_file.write(data)
    # Temporary file automatically deleted
    """
    
    @staticmethod
    @contextmanager
    def secure_tempfile():
        """
        Context manager for creating and using secure temporary files

        Yields:
            tuple: (temporary file object, temporary file path)

        The temporary file is automatically securely deleted after use.
        """
        temp_fd, temp_path = tempfile.mkstemp(prefix='veritas_', suffix='.tmp')
        try:
            # Set file permissions (0600)
            os.chmod(temp_path, 0o600)
            with os.fdopen(temp_fd, 'wb+') as temp_file:
                yield temp_file, temp_path
        finally:
            try:
                # Secure temporary file deletion
                if os.path.exists(temp_path):
                    file_size = os.path.getsize(temp_path)
                    with open(temp_path, 'wb') as f:
                        # 3 overwrites
                        for _ in range(3):
                            f.seek(0)
                            f.write(os.urandom(file_size))
                            f.flush()
                            os.fsync(f.fileno())
                    os.remove(temp_path)
            except Exception as e:
                logger.error(f"Failed to delete temporary file: {e}")



class MultiAlgorithmEncryption:
    """
    Class for securely encrypting and decrypting data using multiple encryption algorithms

    This class protects data by sequentially applying multiple encryption algorithms.
    Each algorithm uses separate keys and initialization vectors (nonce) to enhance security.

    Algorithms used:
    - ChaCha20-Poly1305: Symmetric encryption algorithm combined with message authentication code
    - AES-GCM: Advanced Encryption Standard (AES) in Galois/Counter Mode (GCM)

    Key derivation algorithm:
    - Argon2id: Memory-hardened key derivation function

    Nonce generation algorithm:
    - HKDF: HMAC-based Key Derivation Function

    Key features:
    - Key Derivation:
      Generates secure encryption keys from user-provided passwords.
      Uses Argon2id algorithm for memory-hardened key derivation.
      Derived keys are used independently for each encryption algorithm.

    - Nonce Generation:
      Generates unique nonces for each data chunk during encryption.
      Uses HKDF algorithm to combine base nonce with chunk number and algorithm identifier
      to generate unique nonces.
      
    - Data Encryption and Decryption:
      Divides data into chunks and processes each chunk independently.
      Applies algorithms in sequence: ChaCha20-Poly1305 -> AES-GCM for encryption.
      Applies algorithms in reverse order for decryption to recover original data.
      
    - File Encryption and Decryption:
      Provides functionality to encrypt and decrypt entire files.
      Reads files in chunks for encryption and saves encrypted chunks to file.
      Reads encrypted files in chunks for decryption to restore original files.

    - Integrity Verification:
      Provides functionality to verify encrypted file integrity.
      Checks file headers and metadata, verifies integrity of each chunk.
      Also verifies decryption possibility if password is provided.

    - Password Change:
      Provides functionality to change passwords of encrypted files.
      Decrypts file with existing password, then re-encrypts with new password.

    Usage example:
    encryptor = MultiAlgorithmEncryption()
    encryptor.encrypt_file(input_path, password)
    encryptor.decrypt_file(input_path, password)
    """
    
    # Constants
    ARGON_MEMORY_COST = 2 * 1024 * 1024  # 2GB in KiB (2 * 1024 * 1024 KiB)
    ARGON_TIME_COST = 8
    ARGON_PARALLELISM = 8
    SALT_LENGTH = 32
    NONCE_BASE_LENGTH = 12  # 12-byte nonce for both ChaCha20-Poly1305 and AES-GCM
    BUFFER_SIZE = 1024 * 1024
    KEY_LENGTH = 32  # 256-bit key
    NONCE_INFO_MAGIC = b'VERITAS_NONCE_V1'
    
    def __init__(self, progress_callback: Callable[[Dict[str, Any]], None] = None):
        """
        MultiAlgorithmEncryption class constructor

        Args:
            progress_callback: Callback function to receive progress updates (optional)
        """
        self.progress_callback = progress_callback or (lambda x: None)
        self.secure_memory = SecureMemory()

    def get_file_metadata(self, filepath: str, password: str) -> Optional[VeritasMetadata]:
        """
        Function to read encrypted file metadata

        Args:
            filepath: File path
            password: Password

        Returns:
            Optional[VeritasMetadata]: Metadata object or None
        """
        try:
            with open(filepath, 'rb') as f:
                # Verify header
                fileheader = f.read(len(b'VERITAS10'))
                if fileheader != b'VERITAS10':
                    return None
                
                # Read encryption parameters
                salt = f.read(self.SALT_LENGTH)
                base_nonce = f.read(self.NONCE_BASE_LENGTH)
                
                # Derive key
                keys = self._derive_key(password, salt)
                
                # Read and decrypt metadata
                meta_size = struct.unpack('>I', f.read(4))[0]
                meta_encrypted = f.read(meta_size)
                
                meta_bytes = self.decrypt_chunk(
                    meta_encrypted, keys, base_nonce, 0,
                    b'VERITAS10'
                )
                
                return VeritasMetadata.from_bytes(meta_bytes)
                
        except Exception as e:
            logger.error(f"Failed to read metadata: {str(e)}")
            return None

    def _derive_key(self, password: str, salt: bytes) -> Tuple[bytes, bytes]:
        """
        Function to derive encryption keys from user password using Argon2id
        to generate two keys from the password

        Args:
            password: User password
            salt: Salt value for key derivation

        Returns:
            tuple: Derived keys (for ChaCha20-Poly1305, AES-GCM)

        Raises:
            VeritasSecurityError: On key derivation failure
        """
        try:
            # Generate master key with Argon2id
            hasher = PasswordHasher(
                time_cost=self.ARGON_TIME_COST,
                memory_cost=self.ARGON_MEMORY_COST,
                parallelism=self.ARGON_PARALLELISM,
                hash_len=64,  # 512-bit master key
                type=Type.ID
            )
            
            # Derive master key
            master_key = bytearray(hasher.hash(password.encode(), salt=salt).encode())
            
            # Use HKDF to derive keys for each algorithm
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,  # 256-bit key
                salt=salt,
                info=b'VERITAS_KEY_V1'
            )
            
            # Derive key for ChaCha20-Poly1305
            key1_info = b'ChaCha20Poly1305_Key'
            key1 = bytearray(hkdf.derive(bytes(master_key) + key1_info))
            
            # Derive key for AES-GCM (using new HKDF instance)
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,  # 256-bit key
                salt=salt,
                info=b'VERITAS_KEY_V1'
            )
            key2_info = b'AESGCM_Key'
            key2 = bytearray(hkdf.derive(bytes(master_key) + key2_info))
            
            # Delete master key from memory
            self._secure_memory_cleanup(master_key)
            
            return (key1, key2)
            
        except Exception as e:
            raise VeritasSecurityError(f"Key derivation failed: {str(e)}") from e

    def process_file(self, filepath: str, password: str, mode: str) -> Tuple[bool, str]:
        """
        Process file encryption/decryption
        
        Args:
            filepath: Path of file to process
            password: Password
            mode: 'encrypt' or 'decrypt'
            
        Returns:
            (success status, result file path or error message)
        """
        temp_output = None
    
        try:
            # Create temporary output file
            temp_fd, temp_output = tempfile.mkstemp(prefix='veritas_', suffix='.tmp')
            os.close(temp_fd)  # Close file descriptor
            
            # Process file
            with open(temp_output, 'wb') as output_file:
                if mode == 'encrypt':
                    self.encrypt_file(filepath, password, output_file)
                else:
                    self.decrypt_file(filepath, password, output_file)
                
                # Synchronize file buffer
                output_file.flush()
                os.fsync(output_file.fileno())
            
            return True, temp_output
                
        except Exception as e:
            logger.error(f"File processing failed: {str(e)}", exc_info=True)
            if temp_output and os.path.exists(temp_output):
                try:
                    os.remove(temp_output)
                except:
                    pass
            return False, str(e)
    
    def _derive_nonce(self, base_nonce: bytes, chunk_num: int, stage: int) -> bytes:
        """
        Function to derive unique nonce using HKDF based on chunk number and encryption stage

        Args:
            base_nonce: Base nonce value
            chunk_num: Chunk number
            stage: Encryption stage (0: ChaCha20-Poly1305, 1: AES-GCM)

        Returns:
            bytes: Derived nonce

        Raises:
            VeritasSecurityError: On nonce derivation failure
        """
        try:
            # Create context information
            context = struct.pack(
                '>16sQI',
                self.NONCE_INFO_MAGIC,  # 16-byte magic value
                chunk_num,              # 8-byte chunk number
                stage                   # 4-byte stage number
            )
            
            # Derive nonce using HKDF
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=self.NONCE_BASE_LENGTH,
                salt=None,
                info=context,
            )
            return hkdf.derive(base_nonce)
            
        except Exception as e:
            raise VeritasSecurityError(f"Nonce derivation failed: {e}") from e

    def encrypt_chunk(self, data: bytes, keys: Tuple[bytes, bytes], 
                     base_nonce: bytes, chunk_num: int, aad: bytes) -> bytes:
        """
        Function to encrypt data chunk
        Applies ChaCha20-Poly1305 -> AES-GCM in sequence
        
        Args:
            data: Data to encrypt
            keys: (ChaCha20-Poly1305 key, AES-GCM key)
            base_nonce: Base nonce value
            chunk_num: Chunk number
            aad: Additional authenticated data
        """
        if not isinstance(keys, (tuple, list)) or len(keys) != 2:
            raise VeritasSecurityError("Invalid key format")
    
        chacha_key, aes_key = keys
        
        if not isinstance(chacha_key, (bytes, bytearray)) or not isinstance(aes_key, (bytes, bytearray)):
            raise VeritasSecurityError("Keys are not of correct type")
            
        if len(chacha_key) != 32 or len(aes_key) != 32:
            raise VeritasSecurityError("Invalid key length")
        
        try:
            # Stage 1: ChaCha20-Poly1305
            nonce1 = self._derive_nonce(base_nonce, chunk_num, 0)
            chacha = ChaCha20Poly1305(bytes(chacha_key))  # Convert bytearray to bytes
            ciphertext1 = chacha.encrypt(nonce1, data, aad)
            
            # Stage 2: AES-GCM
            nonce2 = self._derive_nonce(base_nonce, chunk_num, 1)
            aesgcm = AESGCM(bytes(aes_key))  # Convert bytearray to bytes
            ciphertext2 = aesgcm.encrypt(nonce2, ciphertext1, aad)
            
            return ciphertext2
            
        except Exception as e:
            raise VeritasSecurityError(f"Chunk encryption failed: {str(e)}") from e

    def decrypt_chunk(self, data: bytes, keys: Tuple[bytes, bytes], 
                 base_nonce: bytes, chunk_num: int, aad: bytes) -> bytes:
        """
        Function to decrypt encrypted data chunk
        Applies AES-GCM -> ChaCha20-Poly1305 in sequence
        
        Args:
            data: Data to decrypt
            keys: (ChaCha20-Poly1305 key, AES-GCM key)
            base_nonce: Base nonce value
            chunk_num: Chunk number
            aad: Additional authenticated data
        """
        if not isinstance(keys, (tuple, list)) or len(keys) != 2:
            raise VeritasSecurityError("Invalid key format")
    
        chacha_key, aes_key = keys
        
        if not isinstance(chacha_key, (bytes, bytearray)) or not isinstance(aes_key, (bytes, bytearray)):
            raise VeritasSecurityError("Keys are not of correct type")
            
        if len(chacha_key) != 32 or len(aes_key) != 32:
            raise VeritasSecurityError("Invalid key length")
        
        try:
            # Stage 1: AES-GCM decryption
            nonce2 = self._derive_nonce(base_nonce, chunk_num, 1)
            aesgcm = AESGCM(bytes(aes_key))
            try:
                plaintext1 = aesgcm.decrypt(nonce2, data, aad)
            except InvalidTag:
                raise VeritasSecurityError("Invalid password")
            
            # Stage 2: ChaCha20-Poly1305 decryption
            nonce1 = self._derive_nonce(base_nonce, chunk_num, 0)
            chacha = ChaCha20Poly1305(bytes(chacha_key))
            try:
                plaintext = chacha.decrypt(nonce1, plaintext1, aad)
            except InvalidTag:
                raise VeritasSecurityError("Invalid password")
            
            return plaintext
            
        except VeritasSecurityError:
            raise
        except Exception as e:
            raise VeritasSecurityError(f"Decryption failed: {str(e)}")

    def encrypt_file(self, input_path: str, password: str, output_file) -> None:
        """
        Function to encrypt a file

        Args:
            input_path: Path of file to encrypt
            password: User password
            output_file: File object to write encrypted data

        Raises:
            VeritasSecurityError: On file encryption failure
        """
        salt = secrets.token_bytes(self.SALT_LENGTH)
        base_nonce = secrets.token_bytes(self.NONCE_BASE_LENGTH)
        keys = None
        
        try:
            logger.info(f"Starting file encryption: {input_path}")
            logger.debug(f"salt length: {len(salt)}, nonce length: {len(base_nonce)}")
            
            # Key derivation
            try:
                keys = self._derive_key(password, salt)
                logger.debug(f"Key derivation successful, key type: {type(keys)}")
                if isinstance(keys, tuple):
                    logger.debug(f"Key1 type: {type(keys[0])}, Key2 type: {type(keys[1])}")
                    logger.debug(f"Key1 length: {len(keys[0])}, Key2 length: {len(keys[1])}")
            except Exception as e:
                logger.error(f"Key derivation failed: {str(e)}")
                raise
            
            # Extract file extension
            _, extension = os.path.splitext(input_path)
            logger.debug(f"Original file extension: {extension}")
            
            # Prepare metadata
            try:
                metadata = VeritasMetadata(
                    original_size=os.path.getsize(input_path),
                    timestamp=int(os.path.getmtime(input_path)),
                    version=1,
                    extension=extension
                )
                metadata_bytes = metadata.to_bytes()
                logger.debug(f"Metadata creation complete: {metadata}")
                logger.debug(f"Metadata size: {len(metadata_bytes)} bytes")
            except Exception as e:
                logger.error(f"Metadata creation failed: {str(e)}")
                raise
            
            # Encrypt metadata
            try:
                meta_encrypted = self.encrypt_chunk(
                    metadata_bytes, keys, base_nonce, 0,
                    b'VERITAS10'
                )
                logger.debug("Metadata encryption successful")
            except Exception as e:
                logger.error(f"Metadata encryption failed: {str(e)}")
                raise
            
            # Write header
            try:
                output_file.write(b'VERITAS10')
                output_file.write(salt)
                output_file.write(base_nonce)
                output_file.write(struct.pack('>I', len(meta_encrypted)))
                output_file.write(meta_encrypted)
                logger.debug("Header writing complete")
            except Exception as e:
                logger.error(f"Header writing failed: {str(e)}")
                raise
            
            # Encrypt file data
            chunk_num = 1
            total_size = os.path.getsize(input_path)
            processed = 0
            
            logger.debug(f"Total size to process: {total_size} bytes")
            
            with open(input_path, 'rb') as infile:
                while True:
                    try:
                        chunk = infile.read(self.BUFFER_SIZE)
                        if not chunk:
                            break
                        
                        # Encrypt chunk
                        aad = struct.pack('>Q', chunk_num)
                        try:
                            encrypted_chunk = self.encrypt_chunk(chunk, keys, base_nonce, chunk_num, aad)
                            logger.debug(f"Chunk {chunk_num} encryption successful: {len(encrypted_chunk)} bytes")
                        except Exception as e:
                            logger.error(f"Chunk {chunk_num} encryption failed: {str(e)}")
                            raise
                        
                        # Write encrypted chunk
                        try:
                            output_file.write(struct.pack('>I', len(encrypted_chunk)))
                            output_file.write(encrypted_chunk)
                        except Exception as e:
                            logger.error(f"Chunk {chunk_num} writing failed: {str(e)}")
                            raise
                        
                        processed += len(chunk)
                        chunk_num += 1
                        
                        # Update progress
                        self.progress_callback({
                            'stage': 'encryption',
                            'percentage': (processed / total_size) * 100,
                            'bytes_processed': processed,
                            'total_bytes': total_size
                        })
                        
                    except Exception as e:
                        logger.error(f"Error processing chunk {chunk_num}: {str(e)}")
                        raise
                
                # Synchronize file buffer
                output_file.flush()
                os.fsync(output_file.fileno())
                
                logger.info(f"File encryption complete: Processed size {processed} bytes")
                
        except Exception as e:
            logger.error("Encryption failed", exc_info=True)
            raise VeritasSecurityError("File encryption failed") from e
            
        finally:
            # Clean up key memory
            try:
                if keys:
                    logger.debug("Starting key memory cleanup")
                    if isinstance(keys, (tuple, list)):
                        for key in keys:
                            self._secure_memory_cleanup(key)
                    logger.debug("Key memory cleanup complete")
            except Exception as e:
                logger.error(f"Error during key cleanup: {str(e)}")
            finally:
                keys = None

    def _check_available_memory(self, required_bytes: int) -> bool:
        """Check system memory availability"""
        try:
            import psutil
            memory = psutil.virtual_memory()
            return memory.available >= required_bytes
        except ImportError:
            return True  # Skip check if psutil is not available

    def _monitor_memory(self):
        """Monitor memory usage"""
        try:
            import psutil
            process = psutil.Process()
            mem_info = process.memory_info()
            logger.debug(
                f"Memory usage: RSS={mem_info.rss/1024/1024:.2f}MB, "
                f"VMS={mem_info.vms/1024/1024:.2f}MB"
            )
        except ImportError:
            pass
    
    def decrypt_file(self, filepath: str, password: str, output_file) -> None:
        """
        Function to decrypt a file

        Args:
            filepath: Path of file to decrypt
            password: User password
            output_file: File object to write decrypted data

        Raises:
            VeritasSecurityError: On file decryption failure
        """
        keys = None
        
        try:
            logger.info(f"Starting file decryption: {filepath}")
            
            with open(filepath, 'rb') as infile:
                # Verify header
                magic = infile.read(len(b'VERITAS10'))
                if magic != b'VERITAS10':
                    logger.error("Invalid file format")
                    raise VeritasFileError("Invalid file format")
                
                # Read encryption parameters
                salt = infile.read(self.SALT_LENGTH)
                base_nonce = infile.read(self.NONCE_BASE_LENGTH)
                logger.debug(f"salt length: {len(salt)}, nonce length: {len(base_nonce)}")
                
                # Derive key
                try:
                    keys = self._derive_key(password, salt)
                    logger.debug(f"Key derivation successful, key type: {type(keys)}")
                    if isinstance(keys, tuple):
                        logger.debug(f"Key1 type: {type(keys[0])}, Key2 type: {type(keys[1])}")
                        logger.debug(f"Key1 length: {len(keys[0])}, Key2 length: {len(keys[1])}")
                except Exception as e:
                    logger.error(f"Key derivation failed: {str(e)}")
                    raise
                
                # Decrypt metadata
                meta_size = struct.unpack('>I', infile.read(4))[0]
                logger.debug(f"Metadata size: {meta_size}")
                meta_encrypted = infile.read(meta_size)
                
                try:
                    meta_bytes = self.decrypt_chunk(
                        meta_encrypted, keys, base_nonce, 0,
                        b'VERITAS10'
                    )
                    metadata = VeritasMetadata.from_bytes(meta_bytes)
                    logger.debug(f"Metadata decryption successful: {metadata}")
                except Exception as e:
                    logger.error(f"Metadata decryption failed: {str(e)}")
                    raise
                
                # Decrypt file data
                chunk_num = 1
                total_size = metadata.original_size
                processed = 0
                
                logger.debug(f"Total size to process: {total_size} bytes")
                
                while processed < total_size:
                    try:
                        # Read chunk size
                        size_data = infile.read(4)
                        if not size_data:
                            logger.error("File ended prematurely")
                            raise VeritasFileError("File is corrupted")
                        
                        chunk_size = struct.unpack('>I', size_data)[0]
                        logger.debug(f"Chunk {chunk_num} size: {chunk_size}")
                        
                        # Read encrypted chunk
                        encrypted_chunk = infile.read(chunk_size)
                        if not encrypted_chunk or len(encrypted_chunk) != chunk_size:
                            logger.error(f"Chunk size mismatch: expected {chunk_size}, got {len(encrypted_chunk) if encrypted_chunk else 0}")
                            raise VeritasFileError("File is corrupted")
                        
                        # Decrypt chunk
                        aad = struct.pack('>Q', chunk_num)
                        try:
                            decrypted_chunk = self.decrypt_chunk(
                                encrypted_chunk, keys, base_nonce, chunk_num, aad
                            )
                            logger.debug(f"Chunk {chunk_num} decryption successful: {len(decrypted_chunk)} bytes")
                        except Exception as e:
                            logger.error(f"Chunk {chunk_num} decryption failed: {str(e)}")
                            raise
                        
                        # Write decrypted data
                        output_file.write(decrypted_chunk)
                        
                        processed += len(decrypted_chunk)
                        chunk_num += 1
                        
                        # Update progress
                        self.progress_callback({
                            'stage': 'decryption',
                            'percentage': (processed / total_size) * 100,
                            'bytes_processed': processed,
                            'total_bytes': total_size
                        })
                        
                    except Exception as e:
                        logger.error(f"Error processing chunk {chunk_num}: {str(e)}")
                        raise
                
                # Synchronize file buffer
                output_file.flush()
                os.fsync(output_file.fileno())
                
                # Restore original timestamp
                os.utime(output_file.name, (metadata.timestamp, metadata.timestamp))
                
                logger.info(f"File decryption complete: Processed size {processed} bytes")
                    
        except Exception as e:
            logger.error("Decryption failed", exc_info=True)
            raise VeritasSecurityError("File decryption failed") from e
            
        finally:
            # Clean up key memory
            try:
                if keys:
                    logger.debug("Starting key memory cleanup")
                    if isinstance(keys, (tuple, list)):
                        for key in keys:
                            self._secure_memory_cleanup(key)
                    logger.debug("Key memory cleanup complete")
            except Exception as e:
                logger.error(f"Error during key cleanup: {str(e)}")
            finally:
                keys = None

    def verify_file(self, filepath: str, password: Optional[str] = None) -> Tuple[bool, Dict[str, Any]]:
        """
        Function to verify integrity of an encrypted file

        Args:
            filepath: Path of file to verify
            password: User password (optional)

        Returns:
            tuple: (verification success status, verification result information)
        """
        keys = None
        try:
            logger.info(f"Starting file verification: {filepath}")
            
            if not os.path.exists(filepath):
                logger.error("File does not exist")
                return False, {"error": "File does not exist"}
                
            with open(filepath, 'rb') as f:
                # 1. Basic header verification
                magic = f.read(len(b'VERITAS10'))
                logger.debug(f"Magic number: {magic}")
                if magic != b'VERITAS10':
                    logger.error(f"Invalid magic number: {magic}")
                    return False, {"error": "Invalid file format"}
                
                # 2. Verify encryption parameters
                salt = f.read(self.SALT_LENGTH)
                base_nonce = f.read(self.NONCE_BASE_LENGTH)
                logger.debug(f"salt length: {len(salt)}, nonce length: {len(base_nonce)}")
                
                # 3. Verify metadata
                meta_size = struct.unpack('>I', f.read(4))[0]
                logger.debug(f"Metadata size: {meta_size}")
                if meta_size <= 0 or meta_size > 1024 * 1024:
                    logger.error(f"Invalid metadata size: {meta_size}")
                    return False, {"error": "File is corrupted (invalid metadata size)"}
                
                meta_encrypted = f.read(meta_size)
                
                # 4. Verify metadata decryption if password provided
                metadata = None
                if password is not None:
                    try:
                        logger.debug("Starting verification with password")
                        keys = self._derive_key(password, salt)
                        logger.debug(f"Key derivation successful, key type: {type(keys)}")
                        if isinstance(keys, tuple):
                            logger.debug(f"Key1 type: {type(keys[0])}, Key2 type: {type(keys[1])}")
                            logger.debug(f"Key1 length: {len(keys[0])}, Key2 length: {len(keys[1])}")
                        
                        meta_bytes = self.decrypt_chunk(
                            meta_encrypted, keys, base_nonce, 0,
                            b'VERITAS10'
                        )
                        logger.debug("Metadata decryption successful")
                        metadata = VeritasMetadata.from_bytes(meta_bytes)
                        logger.debug(f"Metadata parsing successful: {metadata}")
                    except Exception as e:
                        logger.error(f"Metadata decryption/parsing failed: {str(e)}")
                        return False, {"error": "Invalid password or corrupted metadata"}
                
                # 5. Verify file structure and chunk integrity
                file_size = os.path.getsize(filepath)
                header_size = len(b'VERITAS10') + self.SALT_LENGTH + \
                            self.NONCE_BASE_LENGTH + 4 + meta_size
                
                logger.debug(f"Total file size: {file_size}, header size: {header_size}")
                
                if file_size < header_size:
                    logger.error(f"File size smaller than header: {file_size} < {header_size}")
                    return False, {"error": "File is corrupted (file size)"}
                
                # 6. Verify each chunk
                chunk_count = 0
                current_position = header_size
                expected_size = metadata.original_size if metadata else None
                processed_size = 0
                errors = []
                
                logger.debug("Starting chunk verification")
                
                while current_position < file_size:
                    try:
                        # Read chunk size
                        chunk_size_bytes = f.read(4)
                        if len(chunk_size_bytes) != 4:
                            msg = f"Chunk {chunk_count + 1}: Size data corrupted"
                            logger.error(msg)
                            errors.append(msg)
                            break
                            
                        chunk_size = struct.unpack('>I', chunk_size_bytes)[0]
                        logger.debug(f"Chunk {chunk_count + 1} size: {chunk_size}")
                        
                        if chunk_size <= 0 or chunk_size > self.BUFFER_SIZE + 256:
                            msg = f"Chunk {chunk_count + 1}: Invalid size ({chunk_size})"
                            logger.error(msg)
                            errors.append(msg)
                            break
                        
                        # Read chunk data
                        chunk_data = f.read(chunk_size)
                        if len(chunk_data) != chunk_size:
                            msg = f"Chunk {chunk_count + 1}: Data corrupted (size mismatch)"
                            logger.error(msg)
                            errors.append(msg)
                            break
                        
                        # Verify chunk decryption if password provided
                        if password is not None and keys is not None:
                            try:
                                aad = struct.pack('>Q', chunk_count + 1)
                                decrypted_chunk = self.decrypt_chunk(
                                    chunk_data, keys, base_nonce, chunk_count + 1, aad
                                )
                                processed_size += len(decrypted_chunk)
                                logger.debug(f"Chunk {chunk_count + 1} decryption successful")
                            except Exception as e:
                                msg = f"Chunk {chunk_count + 1}: Decryption failed ({str(e)})"
                                logger.error(msg)
                                errors.append(msg)
                                break
                        
                        current_position += 4 + chunk_size
                        chunk_count += 1
                        
                    except Exception as e:
                        msg = f"Error processing chunk {chunk_count + 1}: {str(e)}"
                        logger.error(msg)
                        errors.append(msg)
                        break
                
                logger.debug(f"Total {chunk_count} chunks verified")
                
                # 7. Final verification
                if errors:
                    return False, {
                        "error": "File integrity verification failed",
                        "details": errors
                    }
                
                if metadata and processed_size != metadata.original_size:
                    msg = f"File size mismatch: expected {metadata.original_size}, actual {processed_size}"
                    logger.error(msg)
                    return False, {
                        "error": "File size mismatch",
                        "expected": metadata.original_size,
                        "actual": processed_size
                    }
                
                # 8. Return successful verification result
                result = {
                    "file_path": filepath,
                    "file_size": file_size,
                    "encrypted_size": file_size - header_size,
                    "chunk_count": chunk_count,
                    "version": 1,
                    "encryption_params": {
                        "salt_size": self.SALT_LENGTH,
                        "nonce_size": self.NONCE_BASE_LENGTH,
                        "algorithms": [
                            "ChaCha20-Poly1305",
                            "AES-256-GCM"
                        ],
                        "argon2_params": {
                            "memory_cost": self.ARGON_MEMORY_COST,
                            "time_cost": self.ARGON_TIME_COST,
                            "parallelism": self.ARGON_PARALLELISM,
                            "hash_length": self.KEY_LENGTH * 2,
                            "type": "Argon2id"
                        }
                    }
                }
                
                # Include metadata information if available
                if metadata:
                    result.update({
                        "original_size": metadata.original_size,
                        "timestamp": metadata.timestamp,
                        "extension": metadata.extension,
                        "verified_content": True
                    })
                
                logger.info("File verification successful")
                return True, result
                    
        except Exception as e:
            logger.error(f"File verification failed: {str(e)}", exc_info=True)
            return False, {"error": f"Error during verification: {str(e)}"}
                
        finally:
            try:
                # Clean up key memory
                if keys:
                    logger.debug("Starting key memory cleanup")
                    if isinstance(keys, (tuple, list)):
                        for key in keys:
                            self._secure_memory_cleanup(key)
                    logger.debug("Key memory cleanup complete")
            except Exception as e:
                logger.error(f"Error during key cleanup: {str(e)}")
            finally:
                keys = None
    
    def _secure_memory_cleanup(self, key_data) -> None:
        """
        Function to securely erase key data from memory

        Args:
            key_data: Key data to erase (bytes or bytearray)
        """
        if isinstance(key_data, bytes):
            # Convert bytes to bytearray as bytes are immutable
            key_data = bytearray(key_data)
        
        if isinstance(key_data, bytearray):
            # Overwrite data with zeros
            for i in range(len(key_data)):
                key_data[i] = 0

    def change_password(self, filepath: str, old_password: str, new_password: str) -> Tuple[bool, str]:
        """
        Function to change password of an encrypted file

        Args:
            filepath: Path of file to change password
            old_password: Existing password
            new_password: New password

        Returns:
            tuple: (password change success status, result message)
        """
        old_keys = None
        new_keys = None
        temp_path = None
        success = False
        result = ""
        
        try:
            logger.info(f"Starting password change: {filepath}")
            
            with open(filepath, 'rb') as f:
                # Verify header
                magic = f.read(len(b'VERITAS10'))
                if magic != b'VERITAS10':
                    raise VeritasFileError("Invalid file format")
                
                # Read current encryption parameters
                current_salt = f.read(self.SALT_LENGTH)
                current_nonce = f.read(self.NONCE_BASE_LENGTH)
                
                # Decrypt metadata with current key
                meta_size = struct.unpack('>I', f.read(4))[0]
                meta_encrypted = f.read(meta_size)
                
                # Derive key with existing password
                try:
                    old_keys = self._derive_key(old_password, current_salt)
                    
                    # Try metadata decryption
                    meta_bytes = self.decrypt_chunk(
                        meta_encrypted, old_keys, current_nonce, 0,
                        b'VERITAS10'
                    )
                    metadata = VeritasMetadata.from_bytes(meta_bytes)
                    
                except VeritasSecurityError as e:
                    logger.error(f"Password verification failed: {str(e)}")
                    return False, str(e)
                except Exception as e:
                    logger.error(f"Metadata processing failed: {str(e)}")
                    return False, "Error occurred while processing metadata"
                
                # Generate new encryption parameters
                new_salt = secrets.token_bytes(self.SALT_LENGTH)
                new_nonce = secrets.token_bytes(self.NONCE_BASE_LENGTH)
                logger.debug("New encryption parameters generated")
                
                # Derive key with new password
                try:
                    new_keys = self._derive_key(new_password, new_salt)
                    logger.debug("New key derivation successful")
                except Exception as e:
                    logger.error(f"New key derivation failed: {str(e)}")
                    raise
                
                # Create temporary file
                temp_fd, temp_path = tempfile.mkstemp(prefix='veritas_', suffix='.tmp')
                os.close(temp_fd)
                logger.debug(f"Temporary file created: {temp_path}")
                
                with open(temp_path, 'wb') as temp_file:
                    # Write new header
                    temp_file.write(b'VERITAS10')
                    temp_file.write(new_salt)
                    temp_file.write(new_nonce)
                    logger.debug("New header written")
                    
                    # Re-encrypt metadata
                    meta_bytes = metadata.to_bytes()
                    logger.debug(f"Metadata converted to bytes: {len(meta_bytes)} bytes")
                    try:
                        new_meta_encrypted = self.encrypt_chunk(
                            meta_bytes, new_keys, new_nonce, 0,
                            b'VERITAS10'
                        )
                        logger.debug("Metadata re-encryption successful")
                    except Exception as e:
                        logger.error(f"Metadata re-encryption failed: {str(e)}")
                        raise
                    
                    temp_file.write(struct.pack('>I', len(new_meta_encrypted)))
                    temp_file.write(new_meta_encrypted)
                    
                    # Re-encrypt file contents
                    chunk_num = 1
                    total_chunks = 0
                    while True:
                        # Read chunk size
                        size_data = f.read(4)
                        if not size_data:
                            break
                            
                        chunk_size = struct.unpack('>I', size_data)[0]
                        encrypted_chunk = f.read(chunk_size)
                        
                        if not encrypted_chunk or len(encrypted_chunk) != chunk_size:
                            logger.error(f"Chunk size mismatch: expected {chunk_size}, got {len(encrypted_chunk) if encrypted_chunk else 0}")
                            raise VeritasFileError("File is corrupted")
                        
                        try:
                            # Decrypt with current key
                            current_aad = struct.pack('>Q', chunk_num)
                            decrypted_chunk = self.decrypt_chunk(
                                encrypted_chunk, old_keys, current_nonce,
                                chunk_num, current_aad
                            )
                            
                            # Re-encrypt with new key
                            new_aad = struct.pack('>Q', chunk_num)
                            new_encrypted_chunk = self.encrypt_chunk(
                                decrypted_chunk, new_keys, new_nonce,
                                chunk_num, new_aad
                            )
                            
                            # Write new encrypted data
                            temp_file.write(struct.pack('>I', len(new_encrypted_chunk)))
                            temp_file.write(new_encrypted_chunk)
                            
                            total_chunks += 1
                            logger.debug(f"Chunk {chunk_num} processing complete")
                            
                        except Exception as e:
                            logger.error(f"Chunk {chunk_num} processing failed: {str(e)}")
                            raise
                        
                        chunk_num += 1
                    
                    logger.debug(f"Total {total_chunks} chunks processed")
                    
                    # Synchronize file buffer
                    temp_file.flush()
                    os.fsync(temp_file.fileno())
                
                # Move temporary file to original file
                shutil.copy2(temp_path, filepath)
                success = True
                result = "Password changed successfully"
                logger.info("Password change operation complete")
                
        except VeritasSecurityError as e:
            return False, str(e)
        except Exception as e:
            logger.error(f"Password change failed: {str(e)}", exc_info=True)
            return False, "Error occurred during password change"
            
        finally:
            # Clean up key memory
            try:
                if old_keys:
                    if isinstance(old_keys, (tuple, list)):
                        for key in old_keys:
                            self._secure_memory_cleanup(key)
                if new_keys:
                    if isinstance(new_keys, (tuple, list)):
                        for key in new_keys:
                            self._secure_memory_cleanup(key)
            except Exception as e:
                logger.error(f"Error during key cleanup: {str(e)}")
            finally:
                old_keys = None
                new_keys = None
                
        return success, result
