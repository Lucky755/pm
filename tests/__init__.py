"""Keep model request artifacts out of working storage, including direct unittest runs."""
import os
import tempfile
import atexit

if not os.environ.get('PM_MODEL_AUDIT_DIR'):
    _model_audit=tempfile.TemporaryDirectory(prefix='pm-test-model-audit-')
    os.environ['PM_MODEL_AUDIT_DIR']=_model_audit.name
    atexit.register(_model_audit.cleanup)
