# Projeto Big Data & Cibersegurança

Projeto acadêmico sobre análise de eventos de segurança com dados do Wazuh, combinando processamento de dados e visualização em um dashboard SecOps.

## 1. Visão geral do projeto

O objetivo é consolidar eventos de segurança e facilitar a análise de alertas, severidades, origens, vulnerabilidades e técnicas da matriz MITRE ATT&CK. O repositório contém um notebook de engenharia de dados e um dashboard web local.

## 2. Engenharia de dados

**Responsável:** Ricardo da Silva Lacerda.

O notebook [`engenharia_dados.ipynb`](engenharia_dados.ipynb) documenta a preparação da base para as análises e dashboards. O processamento registrado inclui:

- Leitura e consolidação de 178 arquivos CSV.
- Verificação de linhas, colunas, valores ausentes e tipos de dados.
- Identificação e remoção de 8.020 registros duplicados.
- Geração da base tratada.

O arquivo `dados_tratados.csv` tem aproximadamente 394 MB e não está versionado neste repositório. A cópia da equipe está disponível [no Google Drive](https://drive.google.com/file/d/112AH7iAGJa-0z9ml6oE0nIFm7U9oNNSu/view?usp=drivesdk) para as análises que precisem da base completa.

## 3. Dashboard SecOps

O dashboard incluído contém 265.894 alertas de severidade 7–15, de 107 agentes, no período de 01/04/2026 a 09/09/2026, sem duplicatas. Os dados agregados usados pelo painel estão em `dados.js`; esse arquivo não substitui a base CSV completa descrita na seção de engenharia.

### Como executar

Abra `index.html` no navegador. O dashboard não exige instalação de dependências e pode funcionar diretamente como arquivo local. Se preferir servir a pasta localmente, execute `python3 -m http.server 8000` e acesse `http://localhost:8000`.

### Recursos

- Filtro por datas, atalhos mensais e seleção de intervalo no gráfico diário.
- Filtro para excluir os alertas "File system full" de 20–21/06, combinável com o período selecionado.
- Gráficos, mapa, indicadores e detalhes interativos para regras, países, hosts, usuários, MITRE ATT&CK, CVEs e outros atributos.
- Busca acionada por `/` para países, IPs, CVEs, regras, hosts, usuários, táticas e técnicas.

Hosts, IPs e usuários estão anonimizados. O mapa representa os países com pontos, sem fronteiras geográficas. Dados de IP de origem e GeoIP estão disponíveis somente para abril.

### Atualizar os dados do painel

Gere `dados.js` no formato `window.FATO = {...}; window.MAPA = {...};`. A lógica de filtros, gráficos e detalhes está em `app.js`; a estrutura da página está em `index.html` e os estilos em `style.css`.

## 4. Arquivos principais

```text
README.md              documentação do projeto
engenharia_dados.ipynb processamento e análise da base completa
index.html             estrutura do dashboard
app.js                 interações e visualizações
dados.js               dados agregados do dashboard
style.css              estilos do dashboard
```
