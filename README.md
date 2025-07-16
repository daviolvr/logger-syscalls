# Logger para syscalls

## 1. Rodando o make
Na raiz do projeto, rode:
```sh
make
```

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
Ainda na raiz do projeto, rode:
```sh
sudo ./build/syscall_monitor <PID>
```

⚠️ OBS: Você pode rodar:
```sh
sudo ./build/syscall_monitor -h
```
para obter ajuda.
