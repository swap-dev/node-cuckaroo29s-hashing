{
    "targets": [
        {
            "target_name": "cuckaroo29s-hashing",
            "sources": [
                "cuckaroo29s.cc",
                "src/blake2b-ref.c"
            ],
            "include_dirs": [
                "src",
                "<!(node -e \"require('nan')\")"
            ]
        }
    ]
}
