# -*- coding: utf-8 -*-
"""
pytest 配置文件
"""
import sys
from pathlib import Path

# 将项目根目录添加到路径
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))
