# SecOps · Painel de Cibersegurança (Wazuh)

Dashboard interativo do projeto **Big Data & Cibersegurança** (Wazuh SIEM).
Base: 265.894 alertas de severidade 7–15, 107 agentes, de 01/04/2026 a 09/09/2026 (sem duplicatas).

## Como abrir
Abra `index.html` com dois cliques. Funciona **offline**, sem servidor e sem instalar nada.
(Opcional, para servir na rede: `python3 -m http.server 8000` dentro desta pasta.)

## Estrutura
```
index.html        estrutura, navegação e filtros
css/style.css     tema escuro, vidro, layout responsivo
js/app.js         filtros, gráficos SVG, tooltips, painel de detalhes, busca
js/dados.js       tabela diária (25.160 linhas) + mapa de pontos, gerada a partir dos CSVs
powerbi/          versão para Power BI: fato_alertas.csv, mitre.csv, tema_dark_cyber.json
```

## Filtro de período
Tudo no painel (KPIs, gráficos, mapa, insights, painel de detalhes e "Onde agir agora") é recalculado para o período escolhido. Três jeitos de escolher:
1. **Datas** inicial e final (campos de data).
2. **Atalhos:** Tudo, Abr, Mai, Jun, Jul, Ago, Set, Últ. 30 dias.
3. **Arrastando** sobre o gráfico "Evolução diária". Clique em "Limpar" para voltar a tudo.

O botão **"Sem o evento 20–21/06"** remove os 162.390 alertas "File system full" (61% da base) e pode ser combinado com qualquer período.

## O que é clicável
Países e bolhas do mapa, IPs, regras (linhas da tabela), níveis e grupos de severidade, dias da linha do tempo, hosts, usuários, Event IDs, táticas e técnicas MITRE, CVEs, severidade e nota CVSS. Cada clique abre o painel lateral com o detalhe **do período selecionado**. Dentro do painel os itens também são clicáveis (botão "voltar" retorna). Cards de KPI e itens de "Onde agir agora" levam à seção correspondente.

## Busca
Tecla `/`: países, IPs, CVEs, regras, hosts, usuários, táticas e técnicas.

## Observações
- O mapa é de pontos, com uma bolha por país (sem fronteiras exatas).
- Hosts, IPs e usuários estão anonimizados na base.
- Só abril tem IP de origem e GeoIP na base (conferido mês a mês). Nos demais períodos o painel mostra um aviso com atalho para abril.
- Para atualizar os dados, regenere `js/dados.js` (formato `window.FATO = {...}; window.MAPA = {...};`).
