# veritas_encryptor_main.py
import os
import sys
import platform
import getpass
from typing import Dict, Any, Optional
from pathlib import Path
from datetime import datetime
from veritas_encryptor_core import *
from logger import *

class VeritasDirectoryManager:
    """
    Class managing directories used by the program

    This class provides functionality to create and manage program working directories.
    Maintains separate directories for encrypted files and decrypted files.

    Key features:
    - Working Directory Setup and Creation:
      Sets up program's base working directory and creates necessary subdirectories.
      Base working directory is the directory where program executable is located.
      Creates 'encrypted' directory for encrypted files and 'decrypted' directory for decrypted files.

    - Original File List Retrieval:
      Returns list of original files in 'original' directory.
      This list is used for file encryption operations.
      
    - Encrypted File List Retrieval:
      Returns list of encrypted files in 'encrypted' directory.
      This list is used for file encryption, decryption, password change, integrity verification operations.

    - Decrypted File List Retrieval:
      Returns list of decrypted files in 'decrypted' directory.
      
    - Output File Path Generation:
      Generates output file path based on input file path and operation mode (encrypt/decrypt).
      Encrypted files are saved to 'encrypted' directory, decrypted files to 'decrypted' directory.

    Usage example:
    dir_manager = VeritasDirectoryManager()
    original_files = dir_manager.get_original_files()
    encrypted_files = dir_manager.get_encrypted_files()
    decrypted_files = dir_manager.get_decrypted_files()
    output_path = dir_manager.get_output_path(input_path, mode)
    """
    
    def __init__(self):
        """
        VeritasDirectoryManager class constructor

        Sets up base working directory and creates necessary subdirectories.
        """
        # Set paths based on actual executable location
        if getattr(sys, 'frozen', False):
            # When built with PyInstaller
            self.base_path = Path(sys.executable).parent
        else:
            # When run as Python script
            self.base_path = Path(os.path.dirname(os.path.abspath(__file__)))
            
        # print(f"Base Path: {self.base_path}")  # For debugging
        
        # Set working directories
        self.original_dir = self.base_path / 'original'
        self.encrypted_dir = self.base_path / 'encrypted'
        self.decrypted_dir = self.base_path / 'decrypted'
        
        # Create directories
        self.setup_directories()
    
    def setup_directories(self):
        """Function to create necessary directories"""
        try:
            for dir_path in [self.original_dir, self.encrypted_dir, self.decrypted_dir]:
                dir_path.mkdir(exist_ok=True)
                # print(f"Directory created/checked: {dir_path}")  # For debugging
        except Exception as e:
            print(f"Error creating directories: {e}")
            raise
    
    def _get_files_from_dir(self, directory: Path) -> list:
        """Function to get file list from specified directory"""
        try:
            if not directory.exists():
                # print(f"Warning: Directory does not exist: {directory}")  # For debugging
                return []
            
            files = list(directory.glob('*.*'))
            # print(f"Files found in {directory}: {len(files)}")  # For debugging
            return files
        except Exception as e:
            # print(f"Error reading directory {directory}: {e}")  # For debugging
            return []
        
    def get_original_files(self) -> list:
        """Function to return list of original files"""
        return self._get_files_from_dir(self.original_dir)
    
    def get_encrypted_files(self) -> list:
        """Function to return list of encrypted files"""
        files = self._get_files_from_dir(self.encrypted_dir)
        # Filter files with .veritas extension
        return [f for f in files if f.suffix == '.veritas']
    
    def get_decrypted_files(self) -> list:
        """Function to return list of decrypted files"""
        return self._get_files_from_dir(self.decrypted_dir)
    
    def get_output_path(self, input_path: Path, mode: str) -> Path:
        """
        Function to generate output file path based on input path and operation mode
        """
        if mode == 'encrypt':
            return self.encrypted_dir / f"{input_path.stem}.veritas"
        else:
            return self.decrypted_dir / f"{input_path.stem}"  # Extension will be added from metadata



class VeritasUI:
    """
    Class handling the program's user interface

    This class provides user interaction in a terminal environment and offers program functionality.
    Includes user input processing, menu display, file selection, and progress indication features.

    Key features:
    - User Interface Initialization:
      Checks terminal color support and initializes directory manager and encryption module.
      Sets up color output at program start.

    - Terminal Color Output:
      Outputs text using supported colors.
      Applies or omits color codes based on terminal color support.

    - Screen Clearing:
      Clears the terminal screen.
      Uses appropriate commands for Windows and Unix-based operating systems.

    - Program Banner Output:
      Displays banner containing program name and description.

    - Main Menu Output:
      Displays main menu with available features and receives user selection.

    - Progress Display:
      Shows progress of file encryption, decryption, integrity verification operations.
      Includes progress bar and processed data size information.

    - Password Input Processing:
      Receives password input from user.
      Requests password confirmation when needed.

    - File Selection Processing:
      Returns user-selected file from given file list.
      Provides options for processing all files and cancellation.

    - Batch File Processing:
      Performs encryption, decryption, integrity verification, password change operations on selected files.

    - Individual Operation Processing:
      Performs encryption, decryption, password change, integrity verification on individual files.
      Calls appropriate operations based on user input and displays results.

    Usage example:
    ui = VeritasUI()
    ui.run()
    """
    
    #  Font colors
    COLORS = {
        'white': '\033[37m',
        'highlight': '\033[38;2;202;255;138m',  # #CAFF8A
        'error': '\033[91m',
        'bold': '\033[1m',
        'end': '\033[0m'
    }
    
    def __init__(self):
        """
        VeritasUI class constructor

        Checks terminal color support and initializes directory manager and encryption module.
        """
        self.supports_color = (
            platform.system() != 'Windows' or 
            'ANSICON' in os.environ
        )
        self.dir_manager = VeritasDirectoryManager()
        self.encryptor = MultiAlgorithmEncryption(
            progress_callback=self.show_progress
        )
        if self.supports_color:
            print(self.COLORS['white'])
    
    def colored(self, text: str, color: str) -> str:
        """
        Function to output text with specified color

        Args:
            text: Text to output
            color: Color name to apply

        Returns:
            str: Color-applied text
        """
        if not self.supports_color:
            return text
        return f"{self.COLORS.get(color, self.COLORS['white'])}{text}{self.COLORS['end']}{self.COLORS['white']}"
    
    def clear_screen(self):
        """
        Function to clear terminal screen
        """
        os.system('cls' if platform.system() == 'Windows' else 'clear')
    
    def print_banner(self):
        """
        Function to display program banner
        """
        banner = self.colored("""
        ╔════════════════════════════════════════╗
        ║                                        ║
        ║            Veritas Encryptor           ║
        ║     File Encryption/Decryption Tool    ║
        ║                                        ║
        ╚════════════════════════════════════════╝
        """, 'highlight')
        print(banner)
    
    def print_menu(self):
        """
        Function to display main menu and return user selection

        Returns:
            str: User-selected menu number
        """
        menu = """
        Available Functions:
        1. File Encryption  - Encrypt files from original folder to encrypted folder
        2. File Decryption  - Decrypt files from encrypted folder to decrypted folder
        3. Change Password  - Change password of files in encrypted folder
        4. File Verification - Verify integrity of files in encrypted folder
        5. Exit

        Select: """
        return input(self.colored(menu, 'highlight'))

    def show_progress(self, progress_info: Dict[str, Any]) -> None:
        """
        Function to display progress status

        Args:
            progress_info: Progress status information
        """
        stage = progress_info.get('stage', '')
        percentage = progress_info.get('percentage', 0)
        bytes_processed = progress_info.get('bytes_processed', 0)
        total_bytes = progress_info.get('total_bytes', 0)
        
        stage_names = {
            'encryption': 'Encryption',
            'decryption': 'Decryption',
            'verification': 'Verification',
            'password_change': 'Password Change'
        }
        
        # Create progress bar
        bar_width = 40
        filled = int(bar_width * percentage / 100)
        bar = '█' * filled + '░' * (bar_width - filled)
        
        # Format processed data size
        if bytes_processed and total_bytes:
            size_info = f" ({bytes_processed:,} / {total_bytes:,} bytes)"
        else:
            size_info = ""
        
        status = f"\r{stage_names.get(stage, stage)}: [{bar}] {percentage:.1f}%{size_info}"
        print(self.colored(status, 'highlight'), end='', flush=True)
        
        # Line break on completion
        if percentage >= 100:
            print()

    def get_password(self, confirm: bool = False) -> str:
        """
        Function to get password input from user

        Args:
            confirm: Whether to require password confirmation

        Returns:
            str: User-entered password
        """
        while True:
            try:
                password = getpass.getpass("Password: ")
                if not password:
                    print(self.colored("Please enter a password.", 'error'))
                    continue
                    
                if confirm:
                    confirm_password = getpass.getpass("Confirm password: ")
                    if password != confirm_password:
                        print(self.colored("Passwords do not match.", 'error'))
                        continue
                
                return password
                
            except (KeyboardInterrupt, EOFError):
                raise
            except Exception as e:
                print(self.colored(f"Error during password input: {e}", 'error'))

    def select_file(self, files: list, operation: str) -> Optional[Path]:
        """
        Function to let user select a file

        Args:
            files: List of available files
            operation: Name of operation to perform

        Returns:
            Optional[Path]: Selected file path (None if not selected)
        """
        if not files:
            return None
            
        print(f"\nAvailable files:")
        for idx, file in enumerate(files, 1):
            print(f"{idx}. {file.name}")
        
        try:
            choice = input("\nSelect file number (Enter = process all, q = cancel): ").strip().lower()
            
            if not choice:
                return 'ALL'
            elif choice == 'q':
                return None
                
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(files):
                    return files[idx]
                else:
                    print(self.colored("Invalid file number.", 'error'))
                    return None
            except ValueError:
                print(self.colored("Please enter a valid number.", 'error'))
                return None
                
        except (KeyboardInterrupt, EOFError):
            return None

    def process_all_files(self, files: list, operation: str, password: str = None, new_password: str = None):
        """
        Function to batch process selected files
        """
        total = len(files)
        
        operations_guide = {
            'encrypt': 'Encryption',
            'decrypt': 'Decryption',
            'verify': 'Verification',
            'change_password': 'Password Change'
        }
        
        print(self.colored(
            f"\nStarting {operations_guide[operation]} operation. (Total {total} files)", 
            'highlight'
        ))
        
        for idx, file in enumerate(files, 1):
            try:
                print(self.colored(
                    f"\n[{idx}/{total}] Processing {file.name} ({operations_guide[operation]})...", 
                    'highlight'
                ))
                
                if operation in ['encrypt', 'decrypt']:
                    if operation == 'decrypt':
                        # First read extension from metadata
                        metadata = self.encryptor.get_file_metadata(str(file), password)
                        if metadata is None:
                            print(self.colored("Failed to read metadata", 'error'))
                            continue
                        
                        # Set output path (including extension)
                        base_output_path = self.dir_manager.get_output_path(file, operation)
                        output_path = Path(str(base_output_path) + metadata.extension)
                    else:
                        output_path = self.dir_manager.get_output_path(file, operation)
                    
                    os.makedirs(os.path.dirname(output_path), exist_ok=True)
                    
                    success, result = self.encryptor.process_file(
                        str(file), password, operation
                    )
                    
                    if success:
                        try:
                            shutil.copy2(result, output_path)
                            os.remove(result)  # Delete temporary file
                            print(self.colored(
                                f"Complete: {output_path.name}", 'highlight'
                            ))
                        except Exception as e:
                            print(self.colored(f"Error moving file: {str(e)}", 'error'))
                            # Clean up on failure
                            if os.path.exists(result):
                                os.remove(result)
                            if os.path.exists(output_path):
                                os.remove(output_path)
                    else:
                        print(self.colored(f"Failed: {result}", 'error'))
                
                elif operation == 'verify':
                    success, result = self.encryptor.verify_file(str(file), password)
                    if success:
                        print(self.colored("Verification successful", 'highlight'))
                    else:
                        print(self.colored(
                            f"Verification failed: {result.get('error')}", 'error'
                        ))
                
                elif operation == 'change_password':
                    success, result = self.encryptor.change_password(
                        str(file), password, new_password
                    )
                    if success:
                        print(self.colored("Password change complete", 'highlight'))
                    else:
                        print(self.colored(f"Password change failed: {result}", 'error'))
                
            except Exception as e:
                print(self.colored(
                    f"Error processing file: {str(e)}", 'error'
                ))

    def process_encryption(self):
        """
        Function to handle file encryption operation
        """
        files = self.dir_manager.get_original_files()
        if not files:
            print(self.colored("\nNo files to encrypt. (original folder is empty)", 'error'))
            return
            
        print(self.colored("""
        Encryption Operation Guide:
        - Encrypts files from original folder to encrypted folder.
        - You can select specific files or process all files.
        - Press Enter to process all files.
        """, 'highlight'))
        
        selected_file = self.select_file(files, "encryption")
        if not selected_file:
            return
        
        try:
            password = self.get_password(confirm=True)
            
            if selected_file == 'ALL':
                self.process_all_files(files, 'encrypt', password)
            else:
                output_path = self.dir_manager.get_output_path(selected_file, 'encrypt')
                # Create directory if it doesn't exist
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                
                print(self.colored(f"\n[1/1] Encrypting {selected_file.name}...", 'highlight'))
                success, result = self.encryptor.process_file(
                    str(selected_file), password, 'encrypt'
                )
                
                if success:
                    try:
                        # Safely copy temporary file then move
                        shutil.copy2(result, output_path)
                        os.remove(result)  # Delete temporary file
                        print(self.colored(
                            f"Complete: {output_path.name}", 'highlight'
                        ))
                    except Exception as e:
                        print(self.colored(f"Error moving file: {str(e)}", 'error'))
                        # Clean up temporary and target files on failure
                        if os.path.exists(result):
                            os.remove(result)
                        if os.path.exists(output_path):
                            os.remove(output_path)
                else:
                    print(self.colored(f"Failed: {result}", 'error'))
                
        except Exception as e:
            print(self.colored(f"Error during encryption: {str(e)}", 'error'))

    def process_decryption(self):
        """
        Function to handle file decryption operation
        """
        files = self.dir_manager.get_encrypted_files()
        if not files:
            print(self.colored("\nNo files to decrypt. (encrypted folder is empty)", 'error'))
            return
            
        print(self.colored("""
        Decryption Operation Guide:
        - Decrypts files from encrypted folder to decrypted folder.
        - You can select specific files or process all files.
        - Press Enter to process all files.
        """, 'highlight'))
        
        selected_file = self.select_file(files, "decryption")
        if not selected_file:
            return
        
        try:
            password = self.get_password()
            
            if selected_file == 'ALL':
                self.process_all_files(files, 'decrypt', password)
            else:
                # First read extension from metadata
                metadata = self.encryptor.get_file_metadata(str(selected_file), password)
                if metadata is None:
                    print(self.colored("Failed to read metadata", 'error'))
                    return
                    
                # Set output path (including extension)
                base_output_path = self.dir_manager.get_output_path(selected_file, 'decrypt')
                output_path = Path(str(base_output_path) + metadata.extension)
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                
                print(self.colored(f"\n[1/1] Decrypting {selected_file.name}...", 'highlight'))
                success, result = self.encryptor.process_file(
                    str(selected_file), password, 'decrypt'
                )
                
                if success:
                    try:
                        # Move temporary file to final location (including extension)
                        shutil.copy2(result, output_path)
                        os.remove(result)  # Delete temporary file
                        print(self.colored(
                            f"Complete: {output_path.name}", 'highlight'
                        ))
                    except Exception as e:
                        print(self.colored(f"Error moving file: {str(e)}", 'error'))
                        # Clean up files
                        if os.path.exists(result):
                            os.remove(result)
                        if os.path.exists(output_path):
                            os.remove(output_path)
                else:
                    print(self.colored(f"Failed: {result}", 'error'))
                    
        except Exception as e:
            print(self.colored(f"Error during decryption: {str(e)}", 'error'))

    def process_password_change(self):
        """
        Function to handle password change operation
        """
        files = self.dir_manager.get_encrypted_files()
        if not files:
            print(self.colored("\nNo files to process. (encrypted folder is empty)", 'error'))
            return
            
        print(self.colored("""
        Password Change Operation Guide:
        - Changes passwords of files in encrypted folder.
        - You can select specific files or process all files.
        - Press Enter to process all files.
        """, 'highlight'))
        
        selected_file = self.select_file(files, "password change")
        if not selected_file:
            return
        
        try:
            print(self.colored("\nEnter current password", 'highlight'))
            old_password = self.get_password()
            
            print(self.colored("\nEnter new password", 'highlight'))
            new_password = self.get_password(confirm=True)
            
            if selected_file == 'ALL':
                self.process_all_files(files, 'change_password', old_password, new_password)
            else:
                print(self.colored(f"\n[1/1] Changing password for {selected_file.name}...", 'highlight'))
                
                # Create temporary file
                temp_fd, temp_path = tempfile.mkstemp(prefix='veritas_', suffix='.tmp')
                os.close(temp_fd)
                
                try:
                    # Copy current file to temporary file
                    shutil.copy2(str(selected_file), temp_path)
                    
                    # Attempt password change
                    success, result = self.encryptor.change_password(
                        temp_path, old_password, new_password
                    )
                    
                    if success:
                        # Replace original file on success
                        shutil.copy2(temp_path, str(selected_file))
                        print(self.colored("Password change complete", 'highlight'))
                    else:
                        print(self.colored(f"Password change failed: {result}", 'error'))
                        
                except Exception as e:
                    print(self.colored(f"Error during password change: {str(e)}", 'error'))
                finally:
                    # Clean up temporary file
                    if os.path.exists(temp_path):
                        os.remove(temp_path)
                    
        except Exception as e:
            print(self.colored(f"Error during password change: {str(e)}", 'error'))

    def process_verification(self):
        """
        Function to handle file integrity verification operation
        """
        files = self.dir_manager.get_encrypted_files()
        if not files:
            print(self.colored("\nNo files to verify. (encrypted folder is empty)", 'error'))
            return
            
        print(self.colored("""
        File Verification Operation Guide:
        - Verifies integrity of files in encrypted folder.
        - You can select specific files or process all files.
        - Press Enter to process all files.
        - Optionally verify decryption possibility using password.
        """, 'highlight'))
        
        selected_file = self.select_file(files, "verification")
        if not selected_file:
            return
        
        try:
            password = self.get_password()
            
            if selected_file == 'ALL':
                # Print verification results for batch processing too
                for file in files:
                    print(self.colored(f"\nVerifying {file.name}...", 'highlight'))
                    success, result = self.encryptor.verify_file(str(file), password)
                    if success:
                        print(self.colored("Verification successful", 'highlight'))
                        self._print_verification_result(result)
                    else:
                        print(self.colored("Verification failed!", 'error'))
                        print(self.colored(f"Error: {result.get('error')}", 'error'))
            else:
                print(self.colored(f"\n[1/1] Verifying {selected_file.name}...", 'highlight'))
                
                try:
                    # Copy to temporary file for verification
                    temp_fd, temp_path = tempfile.mkstemp(prefix='veritas_', suffix='.tmp')
                    os.close(temp_fd)
                    
                    shutil.copy2(str(selected_file), temp_path)
                    success, result = self.encryptor.verify_file(temp_path, password)
                    
                    if success:
                        print(self.colored("Verification successful", 'highlight'))
                        self._print_verification_result(result)  # Print verification results
                    else:
                        print(self.colored("Verification failed!", 'error'))
                        print(self.colored(f"Error: {result.get('error')}", 'error'))
                                
                finally:
                    # Clean up temporary file
                    if os.path.exists(temp_path):
                        os.remove(temp_path)
                        
        except Exception as e:
            print(self.colored(f"Error during verification: {str(e)}", 'error'))

    def _print_verification_result(self, result: Dict[str, Any]) -> None:
        """Print verification results"""
        if not result.get('verified_content', False):
            return
        
        print("\nVerification Results:")
        print(f"File: {Path(result.get('file_path')).name}")
        print(f"File size: {result.get('file_size')} bytes")
        print(f"Encrypted data size: {result.get('encrypted_size')} bytes")
        print(f"Number of chunks: {result.get('chunk_count')}")
        print(f"Version: {result.get('version')}")
        
        if 'original_size' in result:
            print(f"Original size: {result['original_size']} bytes")
            print(f"Timestamp: {datetime.fromtimestamp(result['timestamp'])}")
        
        print("\nEncryption Parameters:")
        params = result.get('encryption_params', {})
        print(f"Salt size: {params.get('salt_size')} bytes")
        print(f"Nonce size: {params.get('nonce_size')} bytes")
        print("Algorithms used:")
        for algo in params.get('algorithms', []):
            print(f"- {algo}")
        
        argon2_params = params.get('argon2_params', {})
        print("\nArgon2id Parameters:")
        print(f"Memory: {argon2_params.get('memory_cost')/1024:.1f} MB")
        print(f"Iterations: {argon2_params.get('time_cost')}")
        print(f"Parallelism: {argon2_params.get('parallelism')}")

if __name__ == "__main__":
    ui = VeritasUI()
    ui.clear_screen()
    ui.print_banner()

    while True:
        choice = ui.print_menu()
        if choice == '1':
            ui.process_encryption()
        elif choice == '2':
            ui.process_decryption()
        elif choice == '3':
            ui.process_password_change()
        elif choice == '4':
            ui.process_verification()
        elif choice == '5':
            print(ui.colored("\nExiting program.", 'highlight'))
            break
        else:
            print(ui.colored("\nInvalid selection.", 'error'))