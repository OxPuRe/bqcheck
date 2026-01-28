"""
Configuration priority: CLI flags > env vars > config file > defaults.

Supports: ~/.bqaudit/config.yaml and ./.bqaudit.yaml
"""

import logging


def configure_logging(verbose: bool = False) -> logging.Logger:
    """
    Configure logging for bqaudit CLI.

    Sets up logging with appropriate level based on verbose flag.
    - verbose=True: DEBUG level (detailed logging)
    - verbose=False: INFO level (normal logging)

    Args:
        verbose: Enable verbose (DEBUG) logging. Defaults to False.

    Returns:
        Configured logger instance for bqaudit

    Example:
        >>> logger = configure_logging(verbose=True)
        >>> logger.debug("This will be shown")
        >>> logger = configure_logging(verbose=False)
        >>> logger.debug("This will be hidden")
    """
    # Get or create logger
    logger = logging.getLogger("bqaudit")

    # Set logging level based on verbose flag
    if verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    # Clear existing handlers to avoid duplicates on reconfiguration
    logger.handlers.clear()

    # Create console handler
    handler = logging.StreamHandler()

    # Set format
    formatter = logging.Formatter(
        fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)

    # Add handler to logger
    logger.addHandler(handler)

    # Prevent propagation to root logger
    logger.propagate = False

    return logger
