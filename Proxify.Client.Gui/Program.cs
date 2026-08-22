using Proxify.Client.Gui;

ApplicationConfiguration.Initialize();

// Вся диагностика ProxySession пишется через Console.Out — в GUI-приложении
// она перенаправляется в журнал на форме (см. MainForm.OnLoad).
Application.Run(new MainForm());
