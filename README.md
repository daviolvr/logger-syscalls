# Logger para syscalls
Para usar, primeiro rode um btop, ou htop e veja o pid que deseja atacar, apos isso, caso ainda nao tenha compilado o programa, 
compile com: gcc -o ptrace ptrace.c -lseccomp 
e para rodar use:
sudo ./ptrace <pid>
