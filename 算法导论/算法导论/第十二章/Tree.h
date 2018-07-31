//
//  Tree.h
//  算法导论
//
//  Created by 温杰 on 2018/5/18.
//  Copyright © 2018年 温杰. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "TTree.h"
#import "TTreeRoot.h"


@interface Tree : NSObject
@property (nonatomic ,strong) TTreeRoot * ttroot;

-(TTree*)ttreeInsert:(int)key;
-(void)frontOrderTreeWalk:(TTree*) node;
-(void)middleOrderTreeWalk:(TTree*) node;
-(TTree *)searchKey:(int)key rootTree:(TTree*)tree;
-(TTree *)ttreeMinimum:(TTree *)tree;
-(TTree *)ttreeMaximum:(TTree *)tree;
///后继
-(TTree *)treeSuccessOr:(TTree *)tree;
///前趋
-(TTree*)treePredecessOr:(TTree*)tree;
-(TTree * )delete:(int)key;
///右旋
-(void)rightRotate:(TTree *)x;
///左旋
-(void)leftRoTate:(TTree *)x;
@end
