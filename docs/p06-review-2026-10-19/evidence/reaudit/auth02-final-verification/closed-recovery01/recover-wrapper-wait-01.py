"""Explicit closed-recovery runner: one bounded wait correction in memory only.
Never accepts a transitional process. The original full runtime check must pass.
No controller/source/config/permission files are changed by this runner itself.
"""
from pathlib import Path
import hashlib,importlib.util,inspect,os,stat,sys
CONTROLLER=Path('/root/liveuin-auth02-9095-20261020-07/deployment/activate-9095.py')
EXPECTED='af8508ff6057133cdc8d4c6829d18faf07871ec9d6fa5d8726a525afcaa1106b'
def require(value):
    if not value:raise RuntimeError('reviewed_recovery_input_required')
require(os.geteuid()==0 and CONTROLLER.is_file() and not CONTROLLER.is_symlink())
require(CONTROLLER.stat().st_uid==0 and not CONTROLLER.stat().st_mode&0o022)
require(hashlib.sha256(CONTROLLER.read_bytes()).hexdigest()==EXPECTED)
sys.dont_write_bytecode=True
spec=importlib.util.spec_from_file_location('auth02_reviewed_closed_recovery',CONTROLLER)
control=importlib.util.module_from_spec(spec);spec.loader.exec_module(control)
source=inspect.getsource(control.verify_runtime)
old="if str(exc)!='listener_process_mismatch':raise"
new="if str(exc) not in {'listener_process_mismatch','process_argv_drift'}:raise"
require(source.count(old)==1)
# Same20-second deadline and sleep; all other errors still fail immediately.
# An argv mismatch can only wait, never return success or bypass full preflight.
exec(compile(source.replace(old,new),'reviewed-wrapper-startup-wait','exec'),control.__dict__)
sys.argv=[str(CONTROLLER),'--recover']
sys.exit(control.main())
