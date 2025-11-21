# TelemetriaTec

<img width="203" height="161" alt="Untitled" src="https://github.com/user-attachments/assets/db1597a5-b592-4d24-b3dd-f08776640e29" />


# Projeto feito para analisar e descobrir possiveis causas de interferências na transmissão do sinal
# Aqui vai um manual de como utilizar essa aplicação localmente

# Tecnologias utilizadas:

-Python(Django, Django-Rest)

-Docker, Docker-Compose, MakeFile, pre-commit

-Javascript(React)

-PostgreSQL

## Passo 1:
### Tenha o python e git já instalado na sua máquina
### em seguida clone o repositório

## Passo 2:
### Usando o terminal do seu OS, entre na pasta do ./telemetriatec, e crie o seu virtualenv usando um desses comandos

**Distro Linux**

```bash
python3 -m venv venv
```

**Windows**

```shell
python -m venv venv
```

(Obs: Caso um desses comandos não funcione e gere um erro na tela, digite esse comando para baixar o comando do virtualenv: ```sudo apt install python3.12-venv```)

## Passo 3
### Agora, dentro da pasta ./telemetriatec/backend
### acesse o virtualenv através desse comando no terminal

**Distro Linux**
```bash
source venv/bin/activate
```

**Windows**
```shell
virtualenv\Scripts\activate.bat
```

## Passo 4
### Instale as bibliotecas necessárias digitando esse comando abaixo no terminal(funciona tanto pra windows quanto para as distros linux):

```bash
pip install -r requirements.txt
```

## Passo 5
###