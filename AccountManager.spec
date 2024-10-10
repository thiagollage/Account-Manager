# -*- mode: python ; coding: utf-8 -*-

import sys
import os
import site
from PyInstaller.utils.hooks import collect_all, collect_submodules

block_cipher = None

# Obter o caminho dos pacotes do site
site_packages = site.getsitepackages()[0]

# Diretório do projeto (use o diretório atual)
project_dir = os.path.abspath(os.getcwd())

# Configuração para ttkbootstrap
ttkbootstrap_path = os.path.join(site_packages, 'ttkbootstrap')
ttkbootstrap_datas = []
for root, dirs, files in os.walk(ttkbootstrap_path):
    for file in files:
        if file.endswith(('.tcl', '.png', '.gif')):
            file_path = os.path.join(root, file)
            relative_path = os.path.relpath(file_path, ttkbootstrap_path)
            ttkbootstrap_datas.append((file_path, os.path.join('ttkbootstrap', os.path.dirname(relative_path))))

# Coletar dados e imports para bibliotecas específicas
reportlab_datas, reportlab_binaries, reportlab_hiddenimports = collect_all('reportlab')
cryptography_datas, cryptography_binaries, cryptography_hiddenimports = collect_all('cryptography')
pil_datas, pil_binaries, pil_hiddenimports = collect_all('PIL')
argon2_datas, argon2_binaries, argon2_hiddenimports = collect_all('argon2')
dotenv_datas, dotenv_binaries, dotenv_hiddenimports = collect_all('dotenv')

# Verificar e incluir arquivo de versão
version_file = os.path.join(project_dir, 'version.txt')
if os.path.exists(version_file):
    version_info = version_file
    version_data = [(version_file, '.')]
else:
    print(f"Aviso: {version_file} não encontrado. Informações de versão não serão incluídas.")
    version_info = None
    version_data = []

# Verificar e incluir ícone
icon_png = os.path.join(project_dir, 'icon.png')
if not os.path.exists(icon_png):
    print(f"Aviso: {icon_png} não encontrado. O ícone não será incluído.")
    icon_data = []
else:
    icon_data = [(icon_png, '.')]

# Adicionar arquivos de configuração
config_files = []
for file in ['.env', '.env.example', 'config.ini', 'CHANGELOG.md', 'LICENSE', 'LICENSE.txt']:
    file_path = os.path.join(project_dir, file)
    if os.path.exists(file_path):
        config_files.append((file_path, '.'))
    else:
        print(f"Aviso: {file} não encontrado em {file_path}")

# Adicionar README.md da pasta docs
readme_path = os.path.join(project_dir, 'docs', 'README.md')
if os.path.exists(readme_path):
    config_files.append((readme_path, 'docs'))
else:
    print(f"Aviso: README.md não encontrado em {readme_path}")

a = Analysis(
    [os.path.join(project_dir, 'AccountManager.py')],
    pathex=[site_packages, project_dir],
    binaries=reportlab_binaries + cryptography_binaries + pil_binaries + argon2_binaries + dotenv_binaries,
    datas=ttkbootstrap_datas + version_data + icon_data + reportlab_datas + cryptography_datas + pil_datas + argon2_datas + dotenv_datas + config_files,
    hiddenimports=[
        'tkinter',
        'tkinter.ttk',
        'tkinter.simpledialog',
        'ttkbootstrap',
        'ttkbootstrap.constants',
        'ttkbootstrap.style',
        'ttkbootstrap.themes',
        'ttkbootstrap.widgets',
        'sqlite3',
        'cryptography',
        'cryptography.fernet',
        'json',
        'logging',
        'webbrowser',
        'reportlab',
        'reportlab.lib',
        'reportlab.pdfgen',
        'reportlab.platypus',
        'PIL',
        'PIL._imagingtk',
        'PIL._tkinter_finder',
        'datetime',
        'PIL.Image',
        'os',
        'hashlib',
        'argon2',
        'argon2.low_level',
        'configparser',
        'dotenv'
    ] + reportlab_hiddenimports + cryptography_hiddenimports + pil_hiddenimports + argon2_hiddenimports + dotenv_hiddenimports + collect_submodules('ttkbootstrap'),
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# Adicionar imports específicos da plataforma
if sys.platform.startswith('win'):
    a.hiddenimports.append('win32com.client')
elif sys.platform.startswith('darwin'):
    a.hiddenimports.append('subprocess')

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='AccountManager',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=icon_png if os.path.exists(icon_png) else None,
    version=version_info
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='AccountManager'
)