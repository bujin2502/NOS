#include <iostream>
#include <stdlib.h>
#include <list>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
#include <thread>
#include <semaphore.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <vector>
#include <queue>

using namespace std;

class Poruka
{
public:
  int posiljatelj;
  int primatelj;
  int vrijeme;
  char tip_poruke;
};

class Proces
{
public:
  int idProcesa;
  int sat;
  list<Poruka> lista_zahtjeva;
  list<int> red_cekanja;
};

class GlobalneVarijable
{
public:
  int broj_procesa;
  int so;
  int broj_odgovora;
  struct sockaddr_in sa;
  queue<Poruka> primljenaPoruka;
  sem_t Semaphore;

  GlobalneVarijable()
  {
    broj_procesa = 0;
    so = 0;
    broj_odgovora = 0;
    sem_init(&Semaphore, 0, 1);
  }

  ~GlobalneVarijable()
  {
    sem_destroy(&Semaphore);
  }
};

GlobalneVarijable globVar;

void otvori(GlobalneVarijable &globVar)
{
  globVar.so = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (globVar.so < 0)
  {
    printf("Greška kreiranja spojne točke: %s\n", strerror(errno));
    exit(0);
  }
}

void pripregni(int idProcesa)
{
  globVar.sa.sin_family = AF_INET;
  globVar.sa.sin_port = htons(10000 + 7 * 10 + idProcesa);
  globVar.sa.sin_addr.s_addr = htonl(INADDR_ANY);
  if (bind(globVar.so, (struct sockaddr *)&globVar.sa, sizeof(globVar.sa)) < 0)
  {
    printf("Pogreška povezivanja spojne točke: %s\n", strerror(errno));
    exit(0);
  }
}

void primi(Proces &proces)
{
  ssize_t vel = sizeof(globVar.sa);
  Poruka p;
  while (true)
  {
    vel = recvfrom(globVar.so, &p, sizeof(p), 0, (struct sockaddr *)&globVar.sa, (socklen_t *)&vel);
    if (vel < 0)
    {
      if (errno == EINTR)
        return;
      printf("Greška primanja: %s\n", strerror(errno));
      exit(0);
    }
    if (vel < sizeof(p))
    {
      printf("Primljena nepotpuna poruka: %s\n", strerror(errno));
      exit(0);
    }
    sem_wait(&globVar.Semaphore);
    printf("P%d primio %c(%d, %d) od P%d\n", proces.idProcesa, p.tip_poruke, p.posiljatelj, p.vrijeme, p.posiljatelj);
    globVar.primljenaPoruka.push(p);
    sem_post(&globVar.Semaphore);
  }
}

void posalji(int idProcesa, Poruka &p)
{
  ssize_t vel;
  globVar.sa.sin_port = htons(10000 + 7 * 10 + idProcesa);
  globVar.sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  vel = sendto(globVar.so, &p, sizeof(p), 0, (struct sockaddr *)&globVar.sa, sizeof(globVar.sa));
  if (vel < 0)
  {
    printf("Greška slanja: %s\n", strerror(errno));
    exit(0);
  }
  if (vel < sizeof(p))
  {
    printf("Poslana je nepotpuna poruka: %s\n", strerror(errno));
    exit(0);
  }
  sem_wait(&globVar.Semaphore);
  printf("P%d poslao %c(%d, %d) k P%d\n", p.posiljatelj, p.tip_poruke, p.posiljatelj, p.vrijeme, p.primatelj);
  sem_post(&globVar.Semaphore);
}

void obrisi(list<Poruka> &listaPoruka, Poruka &poruka)
{
  list<Poruka>::iterator it = listaPoruka.begin();
  while (it != listaPoruka.end())
  {
    if ((*it).posiljatelj == poruka.posiljatelj && (*it).vrijeme == poruka.vrijeme)
    {
      listaPoruka.erase(it++);
      break;
    }
    else
    {
      it++;
    }
  }
}

void pomakniSat(Proces &p, int sat)
{
  if (p.sat < sat)
  {
    p.sat = sat + 1;
  }
  else
  {
    p.sat++;
  }
  printf("T(%d)=%d\n", p.idProcesa, p.sat);
}

bool provjeriPoruke(const Poruka &a, const Poruka &b)
{
  if (a.vrijeme == b.vrijeme && a.posiljatelj < b.posiljatelj)
    return true;
  if (a.vrijeme == b.vrijeme && a.posiljatelj > b.posiljatelj)
    return false;
  if (a.vrijeme < b.vrijeme)
    return true;
  if (a.vrijeme > b.vrijeme)
    return false;
  return true;
}

void obradaZahtjeva(Proces &p)
{
  bool provjera = true;
  Poruka poruka, odgovor;
  sem_wait(&globVar.Semaphore);
  if (!globVar.primljenaPoruka.empty())
  {
    poruka = globVar.primljenaPoruka.front();
    globVar.primljenaPoruka.pop();
    provjera = false;
  }
  sem_post(&globVar.Semaphore);
  if (!provjera)
  {
    if (poruka.tip_poruke == 'Z')
    {
      p.lista_zahtjeva.push_back(poruka);
      p.lista_zahtjeva.sort(provjeriPoruke);
      pomakniSat(p, poruka.vrijeme);
      odgovor.posiljatelj = p.idProcesa;
      odgovor.primatelj = poruka.posiljatelj;
      odgovor.tip_poruke = 'O';
      odgovor.vrijeme = p.sat;
      posalji(odgovor.primatelj, odgovor);
    }
    else if (poruka.tip_poruke == 'O')
    {
      sem_wait(&globVar.Semaphore);
      globVar.broj_odgovora++;
      sem_post(&globVar.Semaphore);
      pomakniSat(p, poruka.vrijeme);
    }
    else if (poruka.tip_poruke == 'I')
    {
      obrisi(p.lista_zahtjeva, poruka);
    }
  }
}

void KO(Proces &p)
{
  Poruka zahtjev, odlazna_poruka;
  zahtjev.posiljatelj = p.idProcesa;
  zahtjev.tip_poruke = 'Z';
  zahtjev.vrijeme = p.sat;
  p.lista_zahtjeva.push_back(zahtjev);
  p.lista_zahtjeva.sort(provjeriPoruke);

  for (int i = 1; i <= globVar.broj_procesa; i++)
  {
    if (i != p.idProcesa)
    {
      zahtjev.primatelj = i;
      posalji(i, zahtjev);
    }
  }

  do
  {
    obradaZahtjeva(p);
  } while ((globVar.broj_odgovora < (globVar.broj_procesa - 1)) || !(p.lista_zahtjeva.front().posiljatelj == p.idProcesa));
  printf("P%d usao u KO.\n", p.idProcesa);
  sleep(3);
  obrisi(p.lista_zahtjeva, zahtjev);
  odlazna_poruka.posiljatelj = p.idProcesa;
  odlazna_poruka.tip_poruke = 'I';
  odlazna_poruka.vrijeme = zahtjev.vrijeme;

  for (int i = 1; i <= globVar.broj_procesa; i++)
  {
    if (i != p.idProcesa)
    {
      odlazna_poruka.primatelj = i;
      posalji(i, odlazna_poruka);
    }
  }
  printf("P%d izisao iz KO.\n", p.idProcesa);
}

void posao(Proces &proces)
{
  otvori(globVar);
  pripregni(proces.idProcesa);
  sem_init(&globVar.Semaphore, 0, 1);
  thread Pthread(primi, ref(proces));
  sleep(2);
  while (true)
  {
    bool provjera = false;
    if (!proces.red_cekanja.empty() && (proces.sat >= proces.red_cekanja.front()))
    {
      provjera = true;
      KO(proces);
      proces.red_cekanja.pop_front();
    }
    obradaZahtjeva(proces);
    if (!provjera)
    {
      sleep(1);
      printf("Dogadaj(%d)\n", proces.idProcesa);
      pomakniSat(proces, 0);
    }
  }
}

int main(int argc, char *argv[])
{
  Proces proces;
  int brojac = 0;
  vector<Proces> vProces(0);

  for (int i = 1; i < argc; i++)
  {
    if (strcmp(argv[i], "@") == 0)
    {
      brojac++;
    }
    if (brojac == 0)
    {
      proces.idProcesa = i;
      proces.sat = atoi(argv[i]);
      vProces.push_back(proces);
    }
    else
    {
      if (!strcmp(argv[i], "@") == 0)
      {
        vProces[brojac - 1].red_cekanja.push_back(atoi(argv[i]));
      }
    }
  }

  globVar.broj_procesa = vProces.size();

  for (int i = 0; i < globVar.broj_procesa; i++)
  {
    if (fork() == 0)
    {
      posao(vProces[i]);
      exit(0);
    }
  }

  for (int i = 0; i < globVar.broj_procesa; i++)
  {
    wait(NULL);
  }

  return 0;
}
