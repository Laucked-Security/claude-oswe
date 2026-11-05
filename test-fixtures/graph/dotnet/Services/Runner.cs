namespace Demo.Services;

using System.Diagnostics;

public class Runner
{
    public void Run(string cmd)
    {
        Exec(cmd);
    }

    public virtual void Exec(string c)
    {
        Process.Start("cmd", c); // VULN
    }

    public void Run(string cmd, int retries)
    {
        Action a = () => Exec(cmd);
        a();
    }
}
