import subprocess


class Base:
    def exec(self, c):
        subprocess.run(c, shell=True)  # VULN


class Runner(Base):
    def run(self, cmd):
        return self.exec(cmd)


class Child(Runner):
    def exec(self, c):
        pass
