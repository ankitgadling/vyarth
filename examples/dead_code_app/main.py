"""Live entry. The only path that runs is main() -> app.service.run()."""

import app.service


def main():
    app.service.run()


if __name__ == "__main__":
    main()
