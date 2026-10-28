Na bazie danych jest zapisywany login, haslo
Server po zalogowaniu przypisuje port urzytkownikowi i zapisuje go ale nie 
w bazie danych tylko w pamieci podrecznej.
Urzytkownicy za pomoca E2EE wysylaja do siebie wiadomosci.

Zrobione:
Serwer ktory rozsyla brodcast do wszystkich polaczonych klientow
Klient ktory moze wysylac i otrzymywac wiadomosci od servera
Admin bazy danych tworzy dodaje itp
Polaczyc baze danych do servera
Obsluga logowania w kliencie

Do zrobienia:
Polaczenie dwuch klientow

Szyfrowanie:
Szyfrowanie logowania AES
Szyfrowanie wiadomosci E2EE
Szyfrowanie wiadomosci grupowych
Mozliwosc P2P klientow



Problem do rozwiazania:
Jak zrobic aby klient ktory jest nie zalogowany czyli offline mialby wyslac
wiadomosc do drugiego z szyfrowaniem E2EE.
Jak zrobic aby chat grupowy mial szyfrowanie E2EE (albo matematyka albo 
cos typu torent czyli kazdy uzytkownik jest polaczony z dwoma nastepnym i 
poprzednim i wysylaja sobie na wzajem az do konca)



Dostępne komendy:
/all <wiadomość>       - wiadomość do wszystkich
/users                 - lista użytkowników online
/connect <login>       - rozpocznij prywatną rozmowę
/private <wiadomość>   - wyślij do rozmówcy
/back                  - wróć do broadcastu
/quit                  - zakończ działanie
