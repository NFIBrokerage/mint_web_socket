defmodule MintWebSocket.MixProject do
  use Mix.Project

  def project do
    [
      app: :mint_web_socket,
      version: "0.1.0",
      elixir: "~> 1.8",
      elixirc_paths: elixirc_paths(Mix.env()),
      erlc_paths: erlc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      test_coverage: [tool: ExCoveralls],
      preferred_cli_env: [
        coveralls: :test,
        "coveralls.html": :test,
        "coveralls.github": :test
      ]
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:mint,
       git: "https://github.com/elixir-mint/mint.git",
       ref: "488a6ba5fd418a52f697a8d5f377c629ea96af92"},
      {:castore, ">= 0.0.0", only: [:dev]},
      {:jason, ">= 0.0.0", only: [:dev, :test]},
      {:cowboy, "~> 2.9", only: [:test]},
      {:excoveralls, "~> 0.14", only: [:test]}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/fixtures"]
  defp elixirc_paths(_), do: ["lib"]

  defp erlc_paths(:test), do: ["src", "test/fixtures"]
  defp erlc_paths(_), do: ["src"]
end
