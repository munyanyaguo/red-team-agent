"""
Code Obfuscation Module using PyArmor

IMPORTANT: This tool should only be used for:
- Protecting intellectual property in Python applications
- Authorized security research on obfuscation techniques
- Testing deobfuscation and reverse engineering tools
- Educational purposes in controlled environments

Unauthorized use for malicious purposes is illegal and unethical.
"""

import logging
import os
import tempfile
import shutil
import subprocess
from typing import Dict, Any, Optional
from datetime import datetime
import uuid

logger = logging.getLogger(__name__)

# Check if pyarmor is available
PYARMOR_AVAILABLE = False
try:
    import pyarmor
    PYARMOR_AVAILABLE = True
    logger.info("PyArmor module loaded successfully")
except ImportError:
    logger.warning("PyArmor not available - code obfuscation functionality limited")
    logger.warning("Install with: pip install pyarmor")


class CodeObfuscator:
    """
    Obfuscates Python code using PyArmor and other techniques.

    IMPORTANT: Only use for authorized security testing and IP protection.
    """

    def __init__(self, workspace_dir: str = '/tmp/redteam_obfuscation'):
        """
        Initialize the code obfuscator.

        Args:
            workspace_dir: Directory for temporary obfuscation work
        """
        self.workspace_dir = workspace_dir
        os.makedirs(workspace_dir, exist_ok=True)

    def obfuscate_code_pyarmor(self, code: str, filename: str = None,
                              obfuscate_level: int = 1) -> Dict[str, Any]:
        """
        Obfuscate Python code using PyArmor.

        Args:
            code: Python code to obfuscate
            filename: Optional filename (defaults to temp name)
            obfuscate_level: Obfuscation level (1-3, higher = more obfuscation)

        Returns:
            Dictionary with obfuscation results
        """
        if not PYARMOR_AVAILABLE:
            return {
                "success": False,
                "error": "PyArmor is not installed. Install with: pip install pyarmor"
            }

        logger.warning(f"Obfuscating Python code with PyArmor (level: {obfuscate_level})")

        # Create temporary workspace
        session_id = str(uuid.uuid4())[:8]
        work_dir = os.path.join(self.workspace_dir, f"session_{session_id}")
        os.makedirs(work_dir, exist_ok=True)

        try:
            # Generate filename if not provided
            if not filename:
                filename = f"script_{session_id}.py"
            elif not filename.endswith('.py'):
                filename += '.py'

            input_file = os.path.join(work_dir, filename)
            output_dir = os.path.join(work_dir, 'dist')

            # Write code to file
            with open(input_file, 'w') as f:
                f.write(code)

            logger.info(f"Input file created: {input_file}")

            # Run PyArmor obfuscation using subprocess
            # PyArmor CLI is more reliable than the API
            cmd = [
                'pyarmor',
                'obfuscate',
                '--output', output_dir,
                input_file
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                logger.error(f"PyArmor obfuscation failed: {result.stderr}")
                return {
                    "success": False,
                    "error": f"PyArmor failed: {result.stderr}",
                    "stdout": result.stdout
                }

            # Read obfuscated code
            obfuscated_file = os.path.join(output_dir, filename)

            if not os.path.exists(obfuscated_file):
                return {
                    "success": False,
                    "error": "Obfuscated file not found",
                    "expected_path": obfuscated_file
                }

            with open(obfuscated_file, 'r') as f:
                obfuscated_code = f.read()

            # Get file sizes
            original_size = len(code)
            obfuscated_size = len(obfuscated_code)

            logger.info(f"Code obfuscated successfully: {original_size} -> {obfuscated_size} bytes")

            return {
                "success": True,
                "technique": "pyarmor",
                "original_code": code[:500] + "..." if len(code) > 500 else code,
                "obfuscated_code": obfuscated_code,
                "original_size": original_size,
                "obfuscated_size": obfuscated_size,
                "size_increase_percent": ((obfuscated_size - original_size) / original_size * 100),
                "filename": filename,
                "obfuscate_level": obfuscate_level,
                "session_id": session_id
            }

        except subprocess.TimeoutExpired:
            logger.error("PyArmor obfuscation timeout")
            return {
                "success": False,
                "error": "Obfuscation timeout (exceeded 30 seconds)"
            }

        except Exception as e:
            logger.error(f"Error during PyArmor obfuscation: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e)
            }

        finally:
            # Cleanup workspace
            try:
                shutil.rmtree(work_dir)
                logger.info(f"Cleaned up workspace: {work_dir}")
            except Exception as e:
                logger.warning(f"Failed to cleanup workspace: {e}")

    def obfuscate_code_simple(self, code: str) -> Dict[str, Any]:
        """
        Apply simple obfuscation techniques (variable renaming, etc.).

        Args:
            code: Python code to obfuscate

        Returns:
            Dictionary with obfuscation results
        """
        logger.info("Applying simple code obfuscation")

        try:
            # Simple obfuscation techniques
            obfuscated = code

            # 1. Remove comments
            lines = obfuscated.split('\n')
            lines_no_comments = []
            for line in lines:
                # Remove full-line comments
                stripped = line.strip()
                if not stripped.startswith('#'):
                    # Remove inline comments (basic)
                    if '#' in line:
                        # Be careful not to remove # in strings
                        parts = line.split('#')
                        if len(parts) > 1:
                            # Simple heuristic: keep # if it's in quotes
                            if "'" not in parts[0] and '"' not in parts[0]:
                                line = parts[0]
                    lines_no_comments.append(line)

            obfuscated = '\n'.join(lines_no_comments)

            # 2. Remove docstrings (simple approach)
            obfuscated = obfuscated.replace('"""', '')
            obfuscated = obfuscated.replace("'''", '')

            # 3. Remove extra whitespace
            lines = obfuscated.split('\n')
            lines_trimmed = [line.rstrip() for line in lines if line.strip()]
            obfuscated = '\n'.join(lines_trimmed)

            return {
                "success": True,
                "technique": "simple",
                "original_code": code,
                "obfuscated_code": obfuscated,
                "original_size": len(code),
                "obfuscated_size": len(obfuscated),
                "size_reduction_percent": ((len(code) - len(obfuscated)) / len(code) * 100),
                "note": "Simple obfuscation: removed comments and docstrings"
            }

        except Exception as e:
            logger.error(f"Simple obfuscation error: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def obfuscate_code_base64(self, code: str) -> Dict[str, Any]:
        """
        Obfuscate Python code using Base64 encoding with exec wrapper.

        Args:
            code: Python code to obfuscate

        Returns:
            Dictionary with obfuscation results
        """
        logger.info("Obfuscating code with Base64 wrapper")

        try:
            import base64

            # Encode the code
            encoded = base64.b64encode(code.encode()).decode()

            # Create wrapper script
            wrapper = f"""import base64
exec(base64.b64decode('{encoded}').decode())
"""

            return {
                "success": True,
                "technique": "base64_exec",
                "original_code": code[:500] + "..." if len(code) > 500 else code,
                "obfuscated_code": wrapper,
                "original_size": len(code),
                "obfuscated_size": len(wrapper),
                "note": "Base64 encoded with exec wrapper"
            }

        except Exception as e:
            logger.error(f"Base64 obfuscation error: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def obfuscate_code_marshal(self, code: str) -> Dict[str, Any]:
        """
        Obfuscate Python code using marshal serialization.

        Args:
            code: Python code to obfuscate

        Returns:
            Dictionary with obfuscation results
        """
        logger.info("Obfuscating code with marshal")

        try:
            import marshal
            import base64

            # Compile code to bytecode
            compiled = compile(code, '<string>', 'exec')

            # Serialize bytecode
            marshaled = marshal.dumps(compiled)

            # Encode to base64 for transport
            encoded = base64.b64encode(marshaled).decode()

            # Create wrapper script
            wrapper = f"""import marshal, base64
exec(marshal.loads(base64.b64decode('{encoded}')))
"""

            return {
                "success": True,
                "technique": "marshal",
                "original_code": code[:500] + "..." if len(code) > 500 else code,
                "obfuscated_code": wrapper,
                "original_size": len(code),
                "obfuscated_size": len(wrapper),
                "note": "Compiled to bytecode and marshaled"
            }

        except Exception as e:
            logger.error(f"Marshal obfuscation error: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def obfuscate(self, code: str, technique: str = 'pyarmor',
                 filename: str = None) -> Dict[str, Any]:
        """
        Obfuscate Python code using specified technique.

        Args:
            code: Python code to obfuscate
            technique: Obfuscation technique (pyarmor, simple, base64, marshal)
            filename: Optional filename

        Returns:
            Dictionary with obfuscation results
        """
        logger.warning(f"Code obfuscation requested: technique={technique}")

        technique_lower = technique.lower()

        if technique_lower == 'pyarmor':
            return self.obfuscate_code_pyarmor(code, filename)
        elif technique_lower == 'simple':
            return self.obfuscate_code_simple(code)
        elif technique_lower == 'base64':
            return self.obfuscate_code_base64(code)
        elif technique_lower == 'marshal':
            return self.obfuscate_code_marshal(code)
        else:
            return {
                "success": False,
                "error": f"Unknown technique: {technique}",
                "available_techniques": ["pyarmor", "simple", "base64", "marshal"]
            }

    def get_available_techniques(self) -> Dict[str, Any]:
        """Get information about available obfuscation techniques."""
        techniques = {
            "pyarmor": {
                "name": "PyArmor",
                "description": "Professional Python code obfuscation tool",
                "available": PYARMOR_AVAILABLE,
                "strength": "High",
                "reversible": "Difficult",
                "use_case": "Production code protection, IP protection"
            },
            "simple": {
                "name": "Simple Obfuscation",
                "description": "Remove comments and docstrings",
                "available": True,
                "strength": "Low",
                "reversible": "Easy",
                "use_case": "Basic obfuscation, code minification"
            },
            "base64": {
                "name": "Base64 + exec",
                "description": "Base64 encode with exec wrapper",
                "available": True,
                "strength": "Low",
                "reversible": "Easy",
                "use_case": "Simple obfuscation, payload delivery"
            },
            "marshal": {
                "name": "Marshal Bytecode",
                "description": "Compile to bytecode and serialize",
                "available": True,
                "strength": "Medium",
                "reversible": "Medium",
                "use_case": "Bytecode protection, moderate obfuscation"
            }
        }

        return techniques

    def cleanup_workspace(self):
        """Clean up the workspace directory."""
        try:
            if os.path.exists(self.workspace_dir):
                shutil.rmtree(self.workspace_dir)
                logger.info(f"Cleaned up workspace: {self.workspace_dir}")
        except Exception as e:
            logger.error(f"Failed to cleanup workspace: {e}")
