"""Syntax-only Python function metrics. No imports or source execution."""
import ast

def python_functions(text: str,path: str):
    tree=ast.parse(text);results=[]
    class Decisions(ast.NodeVisitor):
        count=1
        def visit_FunctionDef(self,node):pass
        visit_AsyncFunctionDef=visit_FunctionDef
        def visit_Lambda(self,node):pass
        def generic_visit(self,node):
            if isinstance(node,(ast.If,ast.For,ast.AsyncFor,ast.While,ast.IfExp,ast.ExceptHandler)):self.count+=1
            if isinstance(node,ast.BoolOp):self.count+=len(node.values)-1
            if isinstance(node,ast.comprehension):self.count+=1+len(node.ifs)
            if isinstance(node,ast.match_case) and (node.guard is not None or not isinstance(node.pattern,ast.MatchAs) or node.pattern.pattern is not None):self.count+=1
            super().generic_visit(node)
    for node in ast.walk(tree):
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
            visitor=Decisions()
            for statement in node.body:visitor.visit(statement)
            results.append({'path':path,'name':node.name,'line':node.lineno,'complexity':visitor.count})
            if len(results)>2000:raise ValueError('Function metric limit exceeded')
    return results
