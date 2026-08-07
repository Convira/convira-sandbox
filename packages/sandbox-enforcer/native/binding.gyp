{
  "targets": [
    {
      "target_name": "landlock_binding",
      "sources": ["landlock_binding.c"],
      "conditions": [
        ["OS=='linux'", {
          "cflags": ["-std=gnu11", "-Wall", "-Wextra", "-Werror"]
        }]
      ]
    },
    {
      "target_name": "seccomp_compile",
      "sources": ["seccomp_compile.c"],
      "conditions": [
        ["OS=='linux'", {
          "cflags": ["-std=gnu11", "-Wall", "-Wextra", "-Werror"],
          "libraries": ["-lseccomp"]
        }]
      ]
    }
  ]
}
