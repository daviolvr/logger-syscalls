# Logger para syscalls

⚠️ ATENÇÃO: Crie um diretório build/ na raiz para compilar os programas. Também deve rodar o programa no diretório raiz.

## 1. Rodar htop ou btop
Rode o comando htop ou btop e identifique o processo (pelo PID) que deseja atacar

## 2. Compilar o programa
gcc -o build/monitor src/monitor.c -lseccomp

## 3. Rodar o programa
sudo ./build/monitor <PID>

OBS: o PID é o que você escolheu no passo 1.
