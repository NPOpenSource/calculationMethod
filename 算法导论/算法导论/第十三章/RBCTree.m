//
//  RBCTree.m
//  算法导论
//
//  Created by 温杰 on 2018/5/22.
//  Copyright © 2018年 温杰. All rights reserved.
//

#import "RBCTree.h"

typedef enum ColorType {RED, BLACK} ColorType;
typedef struct rbt_t{
    int key;
    struct rbt_t * left;
    struct rbt_t * right;
    struct rbt_t * p;
    ColorType color;
}rbt_t;

typedef struct rbt_root_t{
   struct rbt_t* root;
   struct rbt_t* space;
}rbt_root_t;

struct rbt_root_t* rbt_init(void){
   struct rbt_root_t* T;
    
    T = (rbt_root_t*)malloc(sizeof(rbt_root_t));
    assert( NULL != T);
    
    T->space = (rbt_t*)malloc(sizeof(rbt_t));
    assert(NULL != T->space);
    T->space->color = BLACK;
    T->space->left = T->space->right = NULL;
    T->space->p = NULL;
    
    T->root = T->space;
    
    return T;
}

/*
 *@brief rbtLeftRotate
 *@param[in] T 树根
 *@param[in] x 要进行旋转的结点
 */

void rbtLeftRotate(struct rbt_root_t* T,struct rbt_t* x){
    rbt_t* y = x->right;
    x->right = y->left;
    if(x->right != T->space)
        x->right->p = x;
    
    y->p = x->p;
    if(y->p == T->space){
        T->root = y;
    }else if(y->key < y->p->key)
        y->p->left = y;
    else
        y->p->right = y;
    
    y->left = x;
    x->p = y;
}
/*
 *@brief rbtRightRotate
 *@param[in] 树根
 *@param[in] 要进行旋转的结点
 */
void rbtRightRotate(struct rbt_root_t* T,struct rbt_t* x){
    rbt_t * y = x->left;
    x->left = y->right;
    
    if(T->space != x->left)
        x->left->p = x;
    y->p = x->p;
    if(y->p == T->space)
        T->root = y;
    else if(y->key < y->p->key)
        y->p->left= y;
    else
        y->p->right = y;
    
    y->right = x;
    x->p = y;
}
/*
 *@brief rbt_handleReorient  内部函数 由rbt_insert调用
 *      在两种情况下调用这个函数：
 * 1 x有连个红色儿子
 * 2 x为新插入的结点
 *
 */
void rbt_handleReorient(rbt_root_t* T, rbt_t* x, int k){
    
    //在第一种情况下，进行颜色翻转； 在第二种情况下，相当于对新插入的x点初始化
    x->color = RED;
    x->left->color = x->right->color = BLACK;
    
    //如果x.p为红色，那么x.p一定不是根，x.p.p一定不是T.nil，而且为黑色
    if(  RED == x->p->color){
        x->p->p->color = RED;//此时x, p, x.p.p都为红
        
        if(x->p->key < x->p->p->key){
            if(k > x->p->key){
                x->color = BLACK;//小心地处理颜色
                rbtLeftRotate(T,x->p);
                rbtRightRotate(T,x->p);
            }else{
                x->p->color = BLACK;//小心地处理颜色
                rbtRightRotate(T,x->p->p);
            }
            
        }else{
            if(k < x->p->key){
                x->color = BLACK;
                rbtRightRotate(T,x->p);
                rbtLeftRotate(T,x->p);
            }else{
                x->p->color = BLACK;
                rbtLeftRotate(T,x->p->p);
            }
            
        }
    }
    
    T->root->color = BLACK;//无条件令根为黑色
}
/*
 *@brief brt_insert 插入
 *1 新插入的结点一定是红色的，如果是黑色的，会破坏条件4（每个结点到null叶结点的每条路径有同样数目的黑色结点）
 *2 如果新插入的结点的父亲是黑色的，那么插入完成。 如果父亲是红色的，那么做一个旋转即可。（前提是叔叔是黑色的）
 *3 我们这个插入要保证其叔叔是黑色的。也就是在x下沉过程中，不允许存在两个红色结点肩并肩。
 */
struct rbt_root_t* rbt_insert(struct rbt_root_t* T, int k){
  struct  rbt_t * x, *p;
    x = T->root;
    p = x;
    //令x下沉到叶子上，而且保证一路上不会有同时为红色的兄弟
    while( x != T->space){
        //
        //保证没有一对兄弟同时为红色， 为什么要这么做？
        if(x != T->space)
            if(x->left->color == RED && x->right->color == RED)
                rbt_handleReorient(T,x,k);
        
        p = x;
        if(k<x->key)
            x = x->left;
        else if(k>x->key)
            x = x->right;
        else{
            printf("\n%d已存在\n",k);
            return T;
        }
        
    }
    
    //为x分配空间，并对其进行初始化
    x = (rbt_t *)malloc(sizeof(rbt_t));
    assert(NULL != x);
    x->key = k;
    x->color = RED;
    x->left = x->right = T->space;
    x->p = p;
    
    //让x的父亲指向x
    if(T->root == T->space)
        T->root = x;
    else if(k < p->key)
        p->left = x;
    else
        p->right = x;
    
    //因为一路下来，如果x的父亲是红色，那么x的叔叔肯定不是红色了，这个时候只需要做一下翻转即可。
    rbt_handleReorient(T,x,k);
    
    return T;
}
void rbt_transplant(struct rbt_root_t* T,struct rbt_t* u,struct rbt_t* v){
    if(u->p == T->space)
        T->root = v;
    else if(u == u->p->left)
        u->p->left =v;
    else
        u->p->right = v;
    v->p = u->p;
}


void rbt_inPrint(const struct rbt_root_t* T,struct rbt_t* t){
    if(T->space == t)return ;
    rbt_inPrint(T,t->left);
    if(t->color == RED)
        printf("%3dR",t->key);
    else
        printf("%3dB",t->key);
    rbt_inPrint(T,t->right);
}

void rbt_prePrint(const struct rbt_root_t* T,struct rbt_t* t){
    if(T->space == t)return ;
    if(t->color == RED)
        printf("%3dR",t->key);
    else
        printf("%3dB",t->key);
    rbt_prePrint(T,t->left);
    rbt_prePrint(T,t->right);
}
//打印程序包括前序遍历和中序遍历两个，因为它俩可以唯一确定一棵二叉树
void rbt_print(const struct rbt_root_t* T){
    assert(T!=NULL);
    printf("\n前序遍历 ：");
    rbt_prePrint(T,T->root);
    printf("\n中序遍历 ：");
    rbt_inPrint(T,T->root);
    printf("\n");
}

void rbt_test(){
    rbt_root_t* T = rbt_init();
    
    T = rbt_insert(T,11);
    T = rbt_insert(T,7);
    T = rbt_insert(T,1);
    T = rbt_insert(T,2);
    T = rbt_insert(T,8);
    T = rbt_insert(T,14);
    T = rbt_insert(T,15);
    T = rbt_insert(T,5);
    T = rbt_insert(T,4);
    
    T = rbt_insert(T,4); //重复插入测试
    rbt_print(T);
    

    
//    rbt_delete(T,8);
//    rbt_delete(T,14);rbt_delete(T,7);rbt_delete(T,11);
//
//    rbt_delete(T,8);//删除不存在的元素
    rbt_print(T);
    
}


@implementation RBCTree

@end
