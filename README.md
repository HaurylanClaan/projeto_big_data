# Projeto Big Data & Cibersegurança

Projeto acadêmico de análise de logs de segurança coletados com Wazuh. O foco do trabalho é organizar e tratar os dados para explorar eventos e identificar informações úteis sobre segurança.

## Etapas do projeto

- Organização dos logs e criação da base de dados anonimizada.
- Tratamento e preparação dos dados para análise.
- Criação de um dashboard para visualizar alertas e padrões de segurança.
- Documentação do projeto, incluindo o uso de Big Data e a anonimização dos dados conforme a LGPD.

## Equipe

### Haurylan Claan — estrutura do projeto e criação da base de dados

Organizou a estrutura do repositório e preparou a base inicial para reunir os logs do projeto em um formato que pudesse ser utilizado nas etapas de tratamento e análise. Essa contribuição estabeleceu os arquivos e os dados de partida para o trabalho da equipe.

### Ricardo da Silva Lacerda — tratamento dos dados

Responsável por preparar os dados para análise. O trabalho inclui ler e consolidar os arquivos de log, verificar a qualidade e os tipos dos dados, identificar registros duplicados e gerar a base tratada para as próximas etapas. O notebook [`engenharia_dados.ipynb`](engenharia_dados.ipynb) registra esse processo.

### Emanuel Bruno — dashboard

Responsável por transformar os dados preparados em visualizações que facilitem a análise dos eventos de segurança. O dashboard apresenta informações como alertas, severidades, origens e padrões observados, ajudando a equipe a explorar os dados e comunicar os resultados.

### Eduardo Nicolau — documentação

Responsável por organizar e redigir a documentação e o relatório do projeto. Essa contribuição descreve as etapas realizadas, o uso de Big Data e as ferramentas envolvidas, além de registrar os cuidados com a anonimização dos dados.

## Fluxo dos dados

1. Os logs são anonimizados e disponibilizados em arquivos CSV.
2. O notebook [`engenharia_dados.ipynb`](engenharia_dados.ipynb) baixa o arquivo original `data_base.rar` do [Release v1.0-dataset](https://github.com/HaurylanClaan/projeto_big_data/releases/download/v1.0-dataset/data_base.rar), extrai os 178 CSVs, combina os dados, remove duplicatas e colunas com excesso de valores vazios.
3. O notebook salva a saída como `/content/base_tratada.csv` no ambiente do Colab.
4. O dashboard carrega os dados compactados de `dados.js`. Esse arquivo foi atualizado a partir da base tratada publicada no [Release dataset-tratado](https://github.com/HaurylanClaan/projeto_big_data/releases/download/dataset-tratado/base_tratada.csv).

O notebook ainda contém uma chamada para montar o Google Drive, mas os arquivos de entrada vêm do GitHub Releases e a saída é salva em `/content`. O dashboard não baixa o CSV: para atualizar os dados publicados no site, é necessário gerar e publicar uma nova versão de `dados.js`.

## Dashboard

O painel apresenta alertas por período, severidade, regra, país de origem, agente, usuário, MITRE ATT&CK, Event ID e vulnerabilidade. É possível filtrar por datas, usar atalhos mensais e abrir detalhes clicando nos gráficos e indicadores. A busca e o filtro para excluir o evento de 20–21/06 foram removidos; o dashboard usa a base completa.

## Arquivos principais

- `engenharia_dados.ipynb`: processamento e análise dos dados.
- `index.html`, `app.js`, `dados.js` e `style.css`: arquivos do dashboard.
- `data_base.rar`: CSVs originais publicados no Release `v1.0-dataset`.
- `base_tratada.csv`: base tratada publicada no Release `dataset-tratado`; o notebook também gera uma cópia em `/content`.

## Licença

O código-fonte deste projeto está sob a licença MIT. A licença não concede direitos sobre bases de dados ou materiais de terceiros; consulte os termos aplicáveis a esses materiais.
