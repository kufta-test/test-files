import os


btype = req.field('backuptype')
cmd = "cmd.exe /K \"c:\\util\\rmanDB.bat " + btype + "&&c:\\util\\cleanup.bat\""
# ruleid: command_injection_generic_practice
os.system(cmd);

home = os.getenv('APPHOME')
cmd = home.join(INITCMD)
# ruleid: command_injection_generic_practice
os.system(cmd)