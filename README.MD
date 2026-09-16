# 🛡️ Projeto Big Data & Cibersegurança:

## 📌 Visão Geral
Este repositório contém a estrutura de scripts e a documentação do projeto de implementação de uma plataforma de cibersegurança baseada em **Big Data e SIEM**. Utilizando a solução open-source Wazuh, o objetivo do projeto é centralizar, correlacionar e analisar em tempo real logs de eventos e ataques cibernéticos simulados.

## 🎯 Objetivos Principais
* **Simulação de Ataques (Red Team):** Geração de tráfego de ameaças reais, como força bruta, varredura de portas, ataques web e malwares.
* **Processamento de Big Data:** Captura e normalização contínua da telemetria de agentes Wazuh.
* **Visualização Analítica:** Construção de dashboards táticos mapeando os incidentes com a matriz MITRE ATT&CK e inteligência de GeoIP.

## 🗄️ Base de Dados (Dataset de 6 Meses)
Para evitar sobrecarga no repositório, o dataset contendo os 6 meses de logs de alta severidade (cerca de 178 arquivos) foi compactado.
👉 **Acesse a aba [Releases](../../releases) deste repositório para baixar a base de dados.**

## 📂 Estrutura do Repositório
* `/scripts`: Códigos em Python utilizados para limpeza, anonimização e concatenação da base de dados.
* `README.md`: Documentação principal do projeto.
