import os
import shutil
import subprocess
import sys

def change_to_correct_directory():
    """Muda para o diretório correto do projeto."""
    current_dir = os.getcwd()
    if os.path.basename(current_dir) == "Account-Manager":
        # Já estamos no diretório correto
        return
    elif os.path.exists("Account-Manager"):
        # Mudar para o diretório Account-Manager
        os.chdir("Account-Manager")
    else:
        print("Erro: Não foi possível encontrar o diretório do projeto.")
        sys.exit(1)

def clean_directories():
    """Remove as pastas build e dist, se existirem."""
    directories_to_remove = ['build', 'dist']
    for directory in directories_to_remove:
        if os.path.exists(directory):
            print(f"Removendo diretório {directory}...")
            shutil.rmtree(directory)

def run_pyinstaller():
    """Executa o PyInstaller com o arquivo spec."""
    spec_file = 'AccountManager.spec'
    if not os.path.exists(spec_file):
        print(f"Arquivo {spec_file} não encontrado!")
        return False

    print("Executando PyInstaller...")
    result = subprocess.run(['pyinstaller', spec_file], check=True)
    return result.returncode == 0

def copy_additional_files():
    """Copia arquivos adicionais para o diretório dist."""
    files_to_copy = ['.env', 'config.ini', 'LICENSE', 'LICENSE.txt', 'version.txt', 'icon.png']
    for file in files_to_copy:
        if os.path.exists(file):
            print(f"Copiando {file} para o diretório dist...")
            shutil.copy(file, 'dist')
        else:
            print(f"Aviso: {file} não encontrado.")

    # Copiar README.md da pasta docs, se existir
    readme_path = os.path.join('docs', 'README.md')
    if os.path.exists(readme_path):
        print("Copiando README.md para o diretório dist...")
        os.makedirs(os.path.join('dist', 'docs'), exist_ok=True)
        shutil.copy(readme_path, os.path.join('dist', 'docs'))
    else:
        print("Aviso: README.md não encontrado na pasta docs.")

def create_version_file():
    """Cria ou atualiza o arquivo version.txt."""
    version = input("Digite a versão do aplicativo (ex: 1.0.0): ")
    with open('version.txt', 'w') as f:
        f.write(version)
    print(f"Arquivo version.txt criado/atualizado com a versão {version}")

def main():
    change_to_correct_directory()

    if not os.path.exists('AccountManager.py'):
        print("Erro: AccountManager.py não encontrado. Certifique-se de estar no diretório correto.")
        sys.exit(1)

    create_version_file()
    clean_directories()
    success = run_pyinstaller()

    if success:
        copy_additional_files()
        print("Build concluído com sucesso!")
    else:
        print("Ocorreu um erro durante o build.")

if __name__ == "__main__":
    main()