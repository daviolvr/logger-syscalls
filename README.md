# Logger para syscalls

## 1. Rodando o make
Na raiz do projeto, rode:
```sh
make
```
para criar o diretório build/ já com os arquivos objeto e o executável.

## 2. Instalando a libseccomp
A libseccomp serve para traduzir números de syscalls em nomes legíveis
```sh
sudo apt install libseccomp-dev
```

## 3. Rodando htop ou btop
Caso não tenha:
```sh
sudo apt install btop
sudo apt install htop
```

Então rode:
```sh
htop
btop
```

E selecione um PID para análise.

## 4. Rodar o programa
Ainda na raiz do projeto, para monitoramento do processo específico passado como argumento, rode:
```sh
sudo ./build/syscall_monitor <PID>
```

ou, caso queira fazer um monitoramento mais abrangente (processos filhos e threads), rode:
```sh
sudo ./build/syscall_monitor <PID> -f
```

⚠️ OBS: Você pode rodar:
```sh
sudo ./build/syscall_monitor -h
```
para obter ajuda.
