AutoSave 1.1.0 — Hard Truck 2: King of the Road

Автосохранение после получения и сдачи груза, победы в кольцевой гонке,
покупки автомобиля, найма водителя и через заданный интервал активной игры.
По умолчанию: 10 минут, три слота, все события и уведомления включены.

autosave_1 — последнее состояние, autosave_2 — предыдущее,
autosave_3 — самое старое. Порядок сохраняется после перезапуска игры.
Мод использует штатное сохранение и не меняет другие ручные слоты.
Запись откладывается до возвращения в активную игру; меню и пауза не входят
в интервал. Несколько событий могут объединяться в одно сохранение.

Установка
1. Требуется рабочий ASI Loader и EXE, соответствующий одному из проверяемых профилей:
   KOTR81 (русская версия 8.1), KOTR13 (международная версия 1.3) или ModifiedCore82.
   Совпадение номера версии само по себе не подтверждает совместимость.
   Версия GOG отдельно не проверялась.
2. Полностью закройте игру. Перед первым использованием сохраните резервную
   копию профиля .pl1. Мод собственных резервных копий не создаёт.
3. При переходе с тестовой версии уберите только HT2_AutoSave_Experimental.asi
   из plugins. Одновременно устанавливать два ASI AutoSave не нужно.
4. Для ручной установки скопируйте plugins из архива в корень игры.
   При установке через Workshop используется ваш обычный менеджер модов.
5. Перезапустите игру и загрузите профиль.

Настройки: plugins/HT2_AutoSave.ini, секция [AutoSave].
Файл создаётся модом при первом входе в мир и не входит в Workshop-пакет.
Существующий файл не изменяется, новые отсутствующие параметры получают
встроенные значения по умолчанию. При ошибке чтения/создания используются
все значения по умолчанию, причина отмечается в IniStatus/IniError.
Если старая опубликованная версия устанавливала INI через синхронизатор,
он мог учитывать его как свой файл: при таком переходе заранее сохраните
настройки отдельно. Новые созданные модом INI в список пакета не входят.
Enabled — включить мод; IntervalEnabled — включить таймер.
IntervalMinutes — интервал 1..1440 минут активной игры.
MaxAutoSaves — число слотов 1..99. ShowNotification — сообщение пейджера.
OnCargoPickup / OnCargoDelivery / OnRaceVictory / OnVehiclePurchase /
OnDriverHire — независимые переключатели событий. Значения true / false.
Изменения применяются после перезапуска. Для сохранения своих настроек
не заменяйте существующий INI образцом при ручном обновлении.

Совместимость и ограничения
Поддерживаются KOTR81 (русская версия 8.1), KOTR13 (международная версия 1.3) и ModifiedCore82 (Game Core 8.2).
Сообщения доступны на RU/EN/FR/DE/ES. Известные KOTR13 EXE для EN/FR/DE/ES;
Локальные EN/DE/ES EXE после последовательных переключений Steam побайтно
совпали по SHA-256 с эталоном KOTR13. Версия GOG отдельно не проверялась;
одинаковый номер версии не подтверждает совместимость.
Неизвестные EXE и конфликты критических сигнатур отключают мод.
Формат сохранений и риск ошибок записи остаются штатными. Все слоты профиля
находятся в общем .pl1: при сбое записи возможна потеря данных всего профиля.
Сдвиг имён тоже не атомарен: ошибка посередине может оставить неполную цепочку.
Уведомление означает возврат штатной функции, а не проверку записи на диск.
При переходе с кольцевой 0.1.2 правильный порядок полностью установится после
N новых автосохранений. Вручную перезаписанные autosave_N не защищены от ротации.

Диагностика: plugins/HT2_AutoSave_Status.ini после входа в мир.
Обычный результат: Result=Ready, Version=1.1.0, ConflictAddress=00000000,
RotationError=00000000. Profile указывает обнаруженный профиль EXE.
IniStatus=Created/Existing и IniError=00000000 — настройки доступны.
ReadFailed/CreateFailed/WriteFailed — использованы встроенные значения.
SignatureConflict/PatchFailed — мод отключён.
RotationFailed — сдвиг остановился с ошибкой, указанной в RotationError;
дальнейшие автоматические попытки отключены до перезапуска.
На неподдерживаемом EXE свежий status может не появиться.
Отключение: Enabled=false и перезапуск либо удаление HT2_AutoSave.asi
при закрытой игре. Существующие автослоты остаются в профиле.

English
AutoSave uses the game's native save function after cargo pickup/delivery,
a circuit race win, a vehicle purchase, a driver hire, and an active-play interval.
Defaults: 10 minutes, three slots, all triggers and pager messages enabled.
autosave_1 is newest, autosave_2 previous, autosave_3 oldest, across restarts.
Menus, pause and lost focus do not count toward the interval. Pending requests
wait for active gameplay; several events may produce one save.

Requires a working ASI Loader. Supports KOTR81 (Russian version 8.1), KOTR13
(international King of the Road 1.3) and ModifiedCore82 (Game Core 8.2).
Known localized KOTR13 executables are supported only when their SHA-256
matches the validated reference. GOG has not been individually verified;
version numbers alone do not establish compatibility.
Close the game before installation. Back up your .pl1 profile before first use.
Remove HT2_AutoSave_Experimental.asi when upgrading from the experimental build;
use only one AutoSave ASI. Copy the plugins folder into the game directory for
manual installation, or use your usual Workshop mod manager. Preserve your INI
when manually updating. The INI is created by the mod if absent and is excluded
from the Workshop package. Existing bytes are never rewritten; missing keys
use built-in defaults. Read/create errors use defaults and set IniStatus/IniError.
For migration from a package that previously shipped the INI, preserve your
settings separately: the synchronizer may still track that older file.
Restart the game after changing the settings above.

Manual slots with other names are not rotated. The native save format and disk
failure risks remain: all profile slots share one .pl1 file. Slot shifting is
not atomic either. Pager messages do not verify successful disk writes.
Ready / Version=1.1.0 in HT2_AutoSave_Status.ini indicates initialized hooks.
RotationFailed disables further automatic attempts until restart.
Disable with Enabled=false or remove HT2_AutoSave.asi while the game is closed.
