import PyInstaller.__main__

PyInstaller.__main__.run([
    'AccountManager.py',
    '--onefile',
    '--windowed',
    '--add-data', 'icon.ico:.',
    '--icon=icon.ico',
    '--name=AccountManager'
])