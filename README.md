# Account Manager
Account Manager é uma aplicação de desktop simples para gerenciar contas de email e senhas. Foi criada por Thiago Lage.

## Funcionalidades

- Adicionar contas (email e senha)
- Editar contas existentes
- Remover contas
- Visualizar lista de contas
- Opção para mostrar/ocultar senhas
- Exportar lista para PDF (funcionalidade não implementada)

## Requisitos

- Python 3.6+
- tkinter
- Pillow (PIL)

## Instalação

1. Clone este repositório:git clone github.com
2. Navegue até o diretório do projeto:
cd account-manager
3. Instale as dependências:
pip install -r requirements.txt

## Uso

Para executar o programa, use o seguinte comando no terminal:
python AccountManager.py

## Criando um executável

Para criar um executável, você pode usar o PyInstaller. Primeiro, instale o PyInstaller:

pip install pyinstaller
Em seguida, use o arquivo .spec fornecido para criar o executável:

pyinstaller AccountManager.spec
O executável será criado na pasta `dist`.

- Executar Alterações: pyinstaller --onefile --windowed AccountManager.py

## Contribuindo

Contribuições são bem-vindas! Por favor, sinta-se à vontade para submeter um Pull Request.

## Licença

Este projeto está licenciado sob a licença MIT. Veja o arquivo `LICENSE` para mais detalhes.

## Contato

Thiago Lage - https://github.com/thiagollage
Estas alterações refletem a mudança do nome do arquivo principal de account_manager.py para AccountManager.py. Certifique-se de que todos os outros arquivos e referências no seu projeto também sejam atualizados para usar o novo nome do arquivo.