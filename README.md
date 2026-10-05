# Projeto Big Data & Cibersegurança

Projeto acadêmico de análise de logs de segurança coletados com Wazuh. O foco do trabalho é organizar e tratar os dados para explorar eventos e identificar informações úteis sobre segurança.

## Etapas do projeto

- Organização dos logs e criação da base de dados.
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

## Arquivos principais

- `engenharia_dados.ipynb`: processamento e análise dos dados.
- `index.html`, `app.js`, `dados.js` e `style.css`: arquivos do dashboard.
- `dados_tratados.csv`: base completa tratada, disponibilizada [no Google Drive da equipe](https://drive.google.com/file/d/112AH7iAGJa-0z9ml6oE0nIFm7U9oNNSu/view?usp=drivesdk)e tambem no releases do github, pois seu tamanho é de aproximadamente 394 MB.

## Licença

O código-fonte deste projeto está sob a licença MIT. A licença não concede direitos sobre bases de dados ou materiais de terceiros; consulte os termos aplicáveis a esses materiais.
