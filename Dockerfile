# Python 3.11の公式イメージを使用
FROM python:3.11-slim-bookworm

# 作業ディレクトリを設定
WORKDIR /app

# システムの依存関係をインストール
# graphvizはdotコマンドを提供
# libxml2-dev, libxslt1-devはlxmlのビルドに必要
# zlib1g-devはその他圧縮ライブラリに必要
# build-essentialはコンパイルに必要なツール群
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    graphviz \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# requirements.txtをコピーしてPython依存関係をインストール
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# アプリケーションのコードをコピー
COPY . .

# ポートを設定 (Gunicornが listenするポート)
EXPOSE 8000

# アプリケーションの起動コマンド
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "app:app"]
