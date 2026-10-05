# SecOps: Painel de Cibersegurança (Wazuh)

Dashboard interativo do projeto **Big Data & Cibersegurança**. A base incluída contém 265.894 alertas de severidade 7–15, 107 agentes e datas de 01/04/2026 a 09/09/2026, sem duplicatas.

## Como executar

Abra `index.html` no navegador. O painel usa arquivos locais e não exige instalação de dependências. Para servi-lo em uma rede local, execute `python3 -m http.server 8000` nesta pasta e abra `http://localhost:8000`.

## Estrutura atual

```text
index.html             página e estrutura do dashboard
style.css              estilos e layout responsivo
app.js                 filtros, gráficos, busca e painel de detalhes
dados.js               dados agregados e coordenadas do mapa
engenharia_dados.ipynb processamento e análise dos dados
data_engineering/      documentação da etapa de engenharia
```

## Recursos do painel

- Filtro de datas, atalhos mensais e seleção de intervalo arrastando sobre o gráfico diário.
- Opção para excluir o evento "File system full" (20–21/06), combinável com o período selecionado.
- Filtros e detalhes interativos para países, regras, hosts, usuários, MITRE ATT&CK, CVEs e outros atributos.
- Busca acionada por `/` para países, IPs, CVEs, regras, hosts, usuários, táticas e técnicas.

KPIs, gráficos, mapa e detalhes acompanham os filtros ativos. O mapa usa pontos por país, sem fronteiras geográficas. Hosts, IPs e usuários estão anonimizados. A base de IPs de origem e GeoIP está disponível somente para abril.

Para atualizar os dados do dashboard, gere novamente `dados.js` no formato `window.FATO = {...}; window.MAPA = {...};`.
