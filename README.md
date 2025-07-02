# Logger para syscalls

## 1. Rodando o make
Na raiz do projeto, rode:
```sh
make
```

## 2. Rodando htop ou btop
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

## 3. Rodar o programa
Ainda na raiz do projeto, rode:
```sh
sudo ./build/syscall_monitor <PID>
```

OBS: o PID é o que você escolheu no passo 2.
