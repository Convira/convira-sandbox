{
  "targets": [
    {
      "target_name": "win_job_object",
      "sources": ["win_job_object.cc"],
      "defines": ["NAPI_VERSION=8"],
      "cflags_cc": ["-std=c++17", "-fexceptions"],
      "xcode_settings": {
        "CLANG_CXX_LANGUAGE_STANDARD": "c++17",
        "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
        "MACOSX_DEPLOYMENT_TARGET": "12.0"
      },
      "msvs_settings": {
        "VCCLCompilerTool": {
          "AdditionalOptions": ["/std:c++17"],
          "ExceptionHandling": 1,
          "PreprocessorDefinitions": ["_WIN32_WINNT=0x0A00"]
        }
      },
      "conditions": [
        ["OS=='win'", { "libraries": ["userenv.lib"] }]
      ]
    },
    {
      "target_name": "convira_sbx_launch",
      "type": "executable",
      "sources": ["win_appcontainer_launch.cc"],
      "cflags_cc": ["-std=c++17", "-fexceptions"],
      "xcode_settings": {
        "CLANG_CXX_LANGUAGE_STANDARD": "c++17",
        "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
        "MACOSX_DEPLOYMENT_TARGET": "12.0"
      },
      "msvs_settings": {
        "VCCLCompilerTool": {
          "AdditionalOptions": ["/std:c++17"],
          "ExceptionHandling": 1,
          "PreprocessorDefinitions": ["_WIN32_WINNT=0x0A00"],
          "RuntimeLibrary": 0
        }
      },
      "conditions": [
        [
          "OS=='win'",
          {
            "libraries": [
              "userenv.lib",
              "ws2_32.lib"
            ]
          }
        ]
      ]
    }
  ]
}
