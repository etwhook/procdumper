
# 🫧 ProcDumper

A Simple Process **Dumper** That Utilizes the Use Of **NtOpenProcess** and **MiniDumpWriteDump** Functions to Work, Written in **Nim**.

## 📽️ Compiling
It's as Simple as Running The Following Command.
```
$ nim c -d:release dumper.nim
```
## 👀 Examples
```
$ ./dumper.exe -n <TARGET_PROC_NAME> -o <DUMP_OUT_PATH>
```
```
$ ./dumper.exe -s Discord.exe -o dump.dmp
```
