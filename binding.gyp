{
  "targets": [
    {
      "target_name": "pattimura",
      "sources": [
        "binding.cc",
        "sync.cc",
        "async.cc",
        "pattimura/pattimura.cc",
        "pattimura/utils.cc",
        "encrypt-decrypt.cc"
      ],
      "include_dirs": [
        "<!(node -e \"require('nan')\")"
      ]
    }
  ]
}
