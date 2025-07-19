module.exports = {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'type-enum': [
      2,
      'always',
      [
        'feat',     // 新功能
        'fix',      // 修复bug
        'docs',     // 文档更新
        'style',    // 代码格式（不影响代码运行的变动）
        'refactor', // 重构（既不是新增功能，也不是修复bug）
        'perf',     // 性能优化
        'test',     // 添加测试
        'build',    // 构建过程或辅助工具的变动
        'ci',       // CI配置文件和脚本的变动
        'chore',    // 其他不修改源代码与测试代码的变动
        'revert'    // 回退某个commit
      ]
    ],
    'scope-enum': [
      2,
      'always',
      [
        'agent',
        'server',
        'web',
        'shared',
        'docker',
        'docs',
        'ci',
        'deps',
        'config',
        'test',
        'scripts'
      ]
    ],
    'subject-case': [2, 'never', ['sentence-case', 'start-case', 'pascal-case', 'upper-case']],
    'subject-full-stop': [2, 'never', '.'],
    'body-leading-blank': [2, 'always'],
    'footer-leading-blank': [2, 'always']
  }
}; 