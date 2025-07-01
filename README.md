# Logger para syscalls
Para usar, primeiro rode um btop, ou htop e veja o PID que deseja atacar, após isso, caso ainda não tenha compilado o programa, 
compile com: gcc -o ptrace ptrace.c -lseccomp 
e para rodar use:
sudo ./ptrace <pid>

Salvar os executáveis na pasta build
