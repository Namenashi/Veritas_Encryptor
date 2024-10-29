import logging

class VeritasError(Exception):
    """Base exception for Veritas"""
    pass

class VeritasSecurityError(Exception):
    """Security related exceptions"""
    pass

class VeritasMemoryError(Exception):
    """Memory related security exceptions"""
    pass

class VeritasFileError(Exception):
    """File related security exceptions"""
    pass

# Security logging configuration
logging.basicConfig(
    # level=logging.INFO, # for debugging
    level=logging.CRITICAL,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("veritas.main")
