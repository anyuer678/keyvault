# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

- fc254f8 chore: 包名 keyvault→keyvault-local（PyPI 名称冲突）
- d0f71ec fix: 删除 requirements.txt 重复声明源（钉死 cryptography==48.0.0 覆盖了 pyproject 的 >=50.0.0），CI 改从 pyproject 安装
- 702bf77 fix: cryptography 下限提至 50.0.0（pip-audit 发现 48.0.0 存在 4 个已知漏洞）
- 8c149ba fix: audit 支持三种密钥赋值风格（dotenv=/yaml:json:/ps1 $env:NAME=），修复 O3 新增用例
- eccdc59 feat: 审计扫描扩展 .yaml/.json/.ps1 + 新增供应商密钥名正则
- c725190 ci: 添加依赖安全审计步骤（npm audit / pip-audit）
- 2f7e42c fix: 补声明 cryptography 依赖（原 dependencies 为空，全新安装后 CLI 导入即崩）
- a9a121e fix: 包布局重构——消除顶层模块污染，修复悬空死入口
- a0bf1a8 fix: 删除 payload_from 死函数（切 tag 的错误实现，无法用于解密）；webui POST 加同源校验
- a7e6138 ci: add pytest CI workflow
- fbf172e fix: 完全重写 pyproject.toml，修复损坏的文件
- 1c37349 fix: pyproject.toml license GPL-3.0 → MIT，与 LICENSE 文件一致
- 9372b6a chore: 删除 AI 开发过程文档
- 959b877 chore: 删除 AI 开发过程文档
- df2aa9b chore: 删除 AI 开发过程文档
- e9d028c chore: 删除 AI 开发过程文档
- e80ebb3 chore: 删除 AI 开发过程文档
- 7be5fbc chore: 删除 AI 开发过程文档
- 8e741ae chore: 替换为标准 SPDX MIT 许可证
- bf67c55 docs: 合并隐私与免责章节

