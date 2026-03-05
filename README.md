# crypto-protocols
Repository with labs on crypto protocols

```bash
> mkdir build
> cd build
> cmake ..
> make
```

## Настроить WinDivert на VS
Скачайте последнюю версию с официального GitHub:
https://github.com/basil00/WinDivert/releases

Скачайте архив, например: WinDivert-2.x.x-A.zip

После распаковки структура будет выглядеть примерно так:

<img width="340" height="232" alt="image" src="https://github.com/user-attachments/assets/a169151c-6582-4df6-bf21-84c82db84909" />

2️⃣ Добавить файлы в проект (Visual Studio)

Предположим, что вы используете x64 проект.

Скопируйте следующие файлы в папку проекта:

<img width="217" height="129" alt="image" src="https://github.com/user-attachments/assets/b19958cb-9e3e-4722-aab7-6b3b57e8ed8f" />


Файлы необходимо взять из следующих папок архива WinDivert:

include/windivert.h

x64/WinDivert.lib

x64/WinDivert.dll

x64/WinDivert64.sys
