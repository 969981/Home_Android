# SQLite 数据库和资源来源链

首轮 `tools/index_db.py` 会创建：
- `apk_files(path PRIMARY KEY, size, compressed_size, crc32, kind, magic_hex)`
- `unity_objects(id, source_path, source_bytes, path_id, type, name, output_path, output_sha256, status, error, tool_version)`

`source_path + path_id` 关联 Unity 对象原生来源；`output_sha256` 用于输出可追溯性。数据库文件由 CSV 重建，不直接提交大体积 SQLite。之后扩展 `resource_links`、`localized_names`、`pokemon_species`、`form_ids`、`item_ids` 及安卓/NS 对照字段。
