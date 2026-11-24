#!/usr/bin/env python3
import bootstrap
import core
import tunnel
if __name__ == '__main__':
    if any((a.startswith('--tunnel') for a in bootstrap.sys.argv[1:])):
        bootstrap.sys.exit(tunnel.tunnel_main(bootstrap.sys.argv[1:]))
    try:
        if bootstrap.sys.platform == 'win32':
            import ctypes

            def _win_ctrl_handler(dw):
                if dw in (0, 1):
                    ctypes.pythonapi.PyErr_SetInterrupt()
                    return True
                return False
            _win_ctrl_cb = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int)(_win_ctrl_handler)
            ctypes.windll.kernel32.SetConsoleCtrlHandler(_win_ctrl_cb, True)
        bootstrap.asyncio.run(core.main())
    except KeyboardInterrupt:
        print('\n[SHUTDOWN] Interrupted by user')
        bootstrap.sys.exit(0)
    except Exception as e:
        print(f'\n{bootstrap.RED}[ERROR] {e}{bootstrap.RESET}')
        bootstrap.traceback.print_exc()
        bootstrap.sys.exit(1)
