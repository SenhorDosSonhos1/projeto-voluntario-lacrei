# Desafio voluntario DevSecOps Lacrei!

## Bandit:

O Bandit é uma ferramenta de segurança de código-fonte específica para Python. Ele é usado para identificar vulnerabilidades e problemas de segurança em código Python. O Bandit faz isso analisando o código-fonte Python em busca de práticas inseguras, uso inadequado de funções e bibliotecas, entre outros problemas comuns de segurança.

## Safety:

O Safety Check atua como um guardião das dependências do nosso projeto. Ele verifica se as bibliotecas que usamos têm vulnerabilidades conhecidas. Isso é importante, já que versões desatualizadas podem representar riscos de segurança. O Safety Check nos ajuda a evitar problemas, garantindo que as dependências que utilizamos não tragam riscos inesperados.

### output safety:
```output
+================================================================================================================================================================================+

                               /$$$$$$            /$$
                              /$$__  $$          | $$
           /$$$$$$$  /$$$$$$ | $$  \__//$$$$$$  /$$$$$$   /$$   /$$
          /$$_____/ |____  $$| $$$$   /$$__  $$|_  $$_/  | $$  | $$
         |  $$$$$$   /$$$$$$$| $$_/  | $$$$$$$$  | $$    | $$  | $$
          \____  $$ /$$__  $$| $$    | $$_____/  | $$ /$$| $$  | $$
          /$$$$$$$/|  $$$$$$$| $$    |  $$$$$$$  |  $$$$/|  $$$$$$$
         |_______/  \_______/|__/     \_______/   \___/   \____  $$
                                                          /$$  | $$
                                                         |  $$$$$$/
  by pyup.io                                              \______/

+================================================================================================================================================================================+

 REPORT 

  Safety is using PyUp's free open-source vulnerability database. This data is 30 days old and limited. 
  For real-time enhanced vulnerability data, fix recommendations, severity reporting, cybersecurity support, team and project policy management and more sign up at
https://pyup.io or email sales@pyup.io

  Safety v2.3.5 is scanning for Vulnerabilities...
  Scanning dependencies in your environment:

  -> d:\estudos\django-estudos\pythonando\projeto_lacrei\venv\lib\site-packages

  Using non-commercial database
  Found and scanned 68 packages
  Timestamp 2023-11-06 19:52:26
  8 vulnerabilities found
  0 vulnerabilities ignored

+================================================================================================================================================================================+ VULNERABILITIES FOUND 
+================================================================================================================================================================================+
-> Vulnerability found in setuptools version 65.5.0
   Vulnerability ID: 52495
   Affected spec: <65.5.1
   ADVISORY: Setuptools 65.5.1 includes a fix for CVE-2022-40897: Python Packaging Authority (PyPA) setuptools before 65.5.1 allows remote attackers to cause a denial of
   service via HTML in a crafted package or custom PackageIndex page. There is a Regular Expression Denial of Service (ReDoS) in package_index.py.https://pyup.io/posts/pyup-...  
   CVE-2022-40897
   For more information, please visit https://pyup.io/v/52495/f17


-> Vulnerability found in webargs version 1.10.0
   Vulnerability ID: 36963
   Affected spec: <5.1.3
   ADVISORY: webargs 5.1.3 fixes race condition between parallel requests when the cache is used. See: CVE-2019-9710.
   CVE-2019-9710
   For more information, please visit https://pyup.io/v/36963/f17


-> Vulnerability found in sqlalchemy version 1.4.50
   Vulnerability ID: 51668
   Affected spec: <2.0.0b1
   ADVISORY: Sqlalchemy 2.0.0b1 avoids leaking cleartext passwords to the open for careless uses of str(engine.URL()) in logs and
   prints.https://github.com/sqlalchemy/sqlalchemy/pull/8563
   PVE-2022-51668
   For more information, please visit https://pyup.io/v/51668/f17


-> Vulnerability found in flask version 1.1.4
   Vulnerability ID: 55261
   Affected spec: <2.2.5
   ADVISORY: Flask 2.2.5 and 2.3.2 include a fix for CVE-2023-30861: When all of the following conditions are met, a response containing data intended for one client may
   be cached and subsequently sent by the proxy to other clients. If the proxy also caches 'Set-Cookie' headers, it may send one client's 'session' cookie to other clients....   
   CVE-2023-30861
   For more information, please visit https://pyup.io/v/55261/f17


-> Vulnerability found in apispec version 0.38.0
   Vulnerability ID: 42246
   Affected spec: <1.0.0b2
   ADVISORY: In PyYAML before 5.1, the yaml.load() API could execute arbitrary code if used with untrusted data. The load() function has been deprecated in version 5.1
   though.https://github.com/kvesteri/sqlalchemy-utils/issues/166https://github.com/kvesteri/sqlalchemy-utils/pull/499
   PVE-2021-42194
   For more information, please visit https://pyup.io/v/42194/f17


-> Vulnerability found in werkzeug version 0.15.6
   Vulnerability ID: 53325
   Affected spec: <2.2.3                                                                        ode. The IV that it uses is not random
   ADVISORY: Werkzeug 2.2.3 includes a fix for CVE-2023-25577: Prior to version 2.2.3, Werkzeug'alchemy-utils/pull/499s multipart form data parser will parse an unlimited number of parts,
   including file parts. Parts can be a small amount of bytes, but each requires CPU time to parse and may use more memory as Python data. If a request can be made to an...
   CVE-2023-25577
   For more information, please visit https://pyup.io/v/53325/f17


-> Vulnerability found in werkzeug version 0.15.6                                               s multipart form data parser will parse an unlimited number of parts,
   Vulnerability ID: 53326                                                                      se and may use more memory as Python data. If a request can be made to an...      
   Affected spec: <2.2.3
   ADVISORY: Werkzeug 2.2.3 includes a fix for CVE-2023-23934: Browsers may allow "nameless" cookies that look like '=value' instead of 'key=value'. A vulnerable browser
   may allow a compromised application on an adjacent subdomain to exploit this to set a cookie 
like '=__Host-test=bad' for another subdomain. Werkzeug prior to 2.2.3 will...
   CVE-2023-23934
   For more information, please visit https://pyup.io/v/53326/f17
                                                                                                kies that look like '=value' instead of 'key=value'. A vulnerable browser
 Scan was completed. 8 vulnerabilities were found.                                              like '=__Host-test=bad' for another subdomain. Werkzeug prior to 2.2.3 will...    

+================================================================================================================================================================================+   REMEDIATIONS

  8 vulnerabilities were found in 7 packages. For detailed remediation & fix recommendations, up=================================================================================+grade to a commercial license.

+===============================================================================================grade to a commercial license.=================================================================================+
  Safety is using PyUp's free open-source vulnerability database. This data is 30 days old and l=================================================================================+imited.
  For real-time enhanced vulnerability data, fix recommendations, severity reporting, cybersecurimited. ity support, team and project policy management and more sign up at                             ity support, team and project policy management and more sign up at
https://pyup.io or email sales@pyup.io

+================================================================================================================================================================================+=================================================================================+
```

## Workflow
####O fluxo de trabalho a seguir está configurado para verificar continuamente o repositório em busca de atualizações. Sempre que ocorrer uma atualização no repositório, o fluxo de trabalho será acionado para buscar possíveis falhas de segurança.
![issue1](https://github.com/SenhorDosSonhos1/projeto-voluntario-lacrei/assets/107871318/23eeebc2-071f-4df6-9ea4-e6a181149262)


#### !!!RELATORIOS GERADOS PELO WORKFLOW!!!
Agora, os passos de upload dos artefatos estão dentro do bloco security_scan e devem ser executados após a execução do Bandit e do Safety Check. Esses artefatos estarão disponíveis para download após a conclusão bem-sucedida do workflow.

![issue2](https://github.com/SenhorDosSonhos1/projeto-voluntario-lacrei/assets/107871318/5df19cba-6c8a-4bb7-94f4-c0e0a2bbf476)

### Codigo utilizado no workflow:
```yml

name: Security Checks

on: [push]

jobs:
  security_scan:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v2

      - name: Setup Python
        uses: actions/setup-python@v2
        with:
          python-version: 3.12

      - name: Install dependencies
        run: |
          pip install bandit safety
      - name: Run Bandit
        run: bandit -r . --format txt -o bandit_results.txt || true  # Este comando pode ignorar os erros e continuar a execução

      - name: Run Safety Check
        run: safety check --json > safety_results.json  # Executa o Safety Check e armazena os resultados em um arquivo JSON

      - name: Upload Bandit results
        if: always()  # Isso garante que os resultados sejam carregados mesmo se houver erros no Bandit
        uses: actions/upload-artifact@v2
        with:
          name: bandit-results
          path: bandit_results.txt

      - name: Upload Safety results
        uses: actions/upload-artifact@v2
        with:
          name: safety-results
          path: safety_results.json


```

