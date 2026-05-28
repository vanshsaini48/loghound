def read_log(path):
    with open(path) as f:
        for line in f:
            print(line.strip())

if __name__ == "__main__":
    read_log("tests/fixtures/sample_auth.log")
