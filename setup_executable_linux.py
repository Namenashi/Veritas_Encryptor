import PyInstaller.__main__
import platform
import sys
import os
from pathlib import Path
import shutil
import site
import glob

def cleanup_build_files():
    """
    Function to clean up temporary files generated during the build process
    
    Items to be removed:
    - build/ : PyInstaller build intermediate files
    - *.spec : PyInstaller spec files
    - __pycache__/ : Python bytecode cache
    """
    print("\nCleaning up temporary files...")
    
    # Delete build folder
    if os.path.exists('build'):
        shutil.rmtree('build')
        print("- build folder deleted")
    
    # Delete .spec files
    spec_files = glob.glob("*.spec")
    for spec_file in spec_files:
        os.remove(spec_file)
        print(f"- {spec_file} deleted")
    
    # Delete __pycache__ folder
    if os.path.exists('__pycache__'):
        shutil.rmtree('__pycache__')
        print("- __pycache__ folder deleted")

def get_site_packages_path():
    """
    Function to return the site-packages path of the current Python environment
    
    Detects and returns the appropriate path for either virtual environment
    or system Python environment
    
    Returns:
        Path: site-packages directory path
    """
    if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        # For virtual environment
        return Path(site.getsitepackages()[0])
    else:
        # For system Python environment
        return Path(site.getsitepackages()[0])

def create_executable(target_platform: str):
    """
    Function to create an executable for the specified platform

    This function uses PyInstaller to build a Python script into a standalone executable.
    Includes special configurations to handle complex dependencies like cryptography
    and argon2 packages.

    Args:
        target_platform (str): Target platform ('Windows' or 'Linux')
    """
    
    # Set output directory
    output_name = f'VeritasEncryptor-{target_platform.lower()}'
    site_packages = get_site_packages_path()
    separator = ':' if platform.system() != 'Windows' else ';'
    
    print(f"\nCurrent settings:")
    print(f"- Python site-packages: {site_packages}")
    print(f"- Target platform: {target_platform}")
    print(f"- Output directory: dist/{output_name}")
    
    # Required binary files
    binary_patterns = [
        "argon2/_ffi*.so",
        "argon2/*.so",
        "cryptography/*.so",
        "cryptography/**/*.so",
        "_cffi_backend*.so",
        "cryptography/hazmat/bindings/*.so",
    ] if platform.system() != 'Windows' else [
        "argon2/_ffi*.dll",
        "argon2/*.pyd",
        "cryptography/*.dll",
        "cryptography/**/*.pyd",
        "_cffi_backend*.pyd",
        "cryptography/hazmat/bindings/*.pyd",
        "*.dll",
    ]
    
    # Find binary files
    binary_options = []
    for pattern in binary_patterns:
        found_files = glob.glob(str(site_packages / pattern), recursive=True)
        for f in found_files:
            if os.path.exists(f):
                binary_options.append(f'--add-binary={f}{separator}.')
                print(f"Found binary: {f}")
    
    # Create runtime hook for executable current location reference
    runtime_hook = """
import os
import sys

# Set path based on actual executable location
if getattr(sys, 'frozen', False):
    application_path = os.path.dirname(sys.executable)
else:
    application_path = os.path.dirname(os.path.abspath(__file__))

# Change working directory to executable location
os.chdir(application_path)
"""
    
    # Create runtime hook file
    hook_file = 'runtime_hook.py'
    with open(hook_file, 'w') as f:
        f.write(runtime_hook)
    
    # PyInstaller options
    options = [
        'veritas_encryptor_main.py',     # Main script
        f'--name={output_name}',         # Output name
        '--onedir',                      # Output as directory
        '--noconfirm',                   # Auto-delete existing build folder
        '--console',                     # Show console window
        '--clean',                       # Clean cache
        f'--runtime-hook={hook_file}',   # Add runtime hook
    ]
    
    # Add required imports
    options.extend([
        '--hidden-import=argon2',
        '--hidden-import=argon2.low_level',
        '--hidden-import=cryptography',
        '--hidden-import=cffi',
        '--hidden-import=_ctypes',
        '--hidden-import=_cffi_backend',
        '--hidden-import=cryptography.hazmat.primitives.ciphers.aead',
        '--hidden-import=cryptography.hazmat.primitives.kdf.hkdf',
        '--hidden-import=cryptography.hazmat.primitives.hashes',
        '--hidden-import=cryptography.hazmat.primitives.ciphers',
        '--hidden-import=cryptography.hazmat.primitives.ciphers.algorithms',
        '--hidden-import=cryptography.hazmat.primitives.ciphers.modes',
        '--hidden-import=cryptography.hazmat.primitives.constant_time',
        '--hidden-import=cryptography.exceptions',
        '--hidden-import=cryptography.hazmat',
        '--hidden-import=cryptography.hazmat.bindings',
        '--hidden-import=cryptography.hazmat.bindings.openssl',
        '--hidden-import=cryptography.hazmat.bindings.openssl.binding',
        
        # Additional argon2 related
        '--hidden-import=argon2.profiles',
        '--hidden-import=argon2._password_hasher',
        '--hidden-import=argon2._utils',
    ])
    
    # Add data files
    options.extend([
        f'--add-data=veritas_encryptor_core.py{separator}.',
        f'--add-data=logger.py{separator}.'
    ])
    
    # Add binary options
    options.extend(binary_options)
    
    print("\nStarting build...")
    
    try:
        # Run PyInstaller
        PyInstaller.__main__.run(options)
        
        # Move and configure result directory
        source_dir = Path('dist') / output_name
        if source_dir.exists():
            # Create working directories
            for dir_name in ['original', 'encrypted', 'decrypted']:
                dir_path = source_dir / dir_name
                dir_path.mkdir(exist_ok=True)
                print(f"Created directory: {dir_path}")
            
            # Add execution permissions on Linux
            if platform.system() != 'Windows':
                exe_path = source_dir / output_name
                if exe_path.exists():
                    os.chmod(exe_path, 0o755)
                    print(f"\nExecution permissions added: {exe_path}")
            
            print(f"\nBuild completed: {source_dir}")
            
        else:
            print("\nBuild failed: Output directory was not created.")
            
    finally:
        # Delete runtime hook file
        if os.path.exists(hook_file):
            os.remove(hook_file)
        
        # Clean up build files
        cleanup_build_files()

def build_all():
    """
    Main function to build executable for the current platform
    
    Detects the current running OS and creates an executable for that platform.
    Handles all exceptions during the build process and outputs logs.
    """
    current_platform = platform.system()
    
    print("Starting Veritas Encryptor deployment package creation...")
    
    try:
        print(f"\nStarting {current_platform} version build...")
        create_executable(current_platform)
    except Exception as e:
        print(f"\nError occurred during {current_platform} version build: {str(e)}")
        import traceback
        print(traceback.format_exc())
    
    print("\nDeployment package creation completed!")
    print(f"Distribution folder: dist/VeritasEncryptor-{current_platform.lower()}/")

if __name__ == "__main__":
    build_all()