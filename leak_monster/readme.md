# Leak Monster
 
The data file, copied below, contains part of the output of the program when you send it a string of 100, "%08x".
```
f7d6668c 64746cd8 7b313268 336d3053 5f336e6f 4c6c4163 505f415f 424d756c 007d7233 78383025 38302520
```

This contains the flag because it is just there in memory, all the script does is parse this data and handle endianness.
